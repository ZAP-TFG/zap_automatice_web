import os
import json
import logging
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from flask_cors import CORS
from datetime import datetime
from extensions import db, app
from flask_migrate import Migrate
from scanner import connect_to_zap, add_url_to_sites, perform_scan, send_email
from schedule_scans import init_scheduler
from models import (
    Escaneres_completados,
    Escaneo_programados,
    Reportes_vulnerabilidades_url,
    Vulnerabilidades_totales,
)
from forms import ScanForm, ChatForm
from pruebas_langchain import graph_memory

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app_logs.log", mode="w", encoding="utf-8")
    ]
)

# Configuración de la aplicación
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zap_data_base.db?journal_mode=WAL&timeout=30'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de CORS (restringido a dominios específicos)
CORS(app, resources={r"/get_calendar_events": {"origins": "http://localhost"}})

# Inicialización de extensiones
db.init_app(app)
migrate = Migrate(app, db)

# Constantes
DATE_FORMAT = '%Y-%m-%dT%H:%M'

# Inicializar el programador de tareas
def init_scheduler_scans():
    init_scheduler()

# Encabezados de seguridad
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src * data: blob: filesystem: 'unsafe-inline' 'unsafe-eval'; img-src * data: blob:;"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

#### Rutas ####

@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    """
    Página principal que muestra estadísticas de escaneos y vulnerabilidades.
    """
    try:
        vul_totales = Vulnerabilidades_totales.query.first()
        data = {
            "scans_completed": vul_totales.escaneos_totales if vul_totales else 0,
            "total_vulnerabilities": vul_totales.vul_all_totales if vul_totales else 0,
            "chart_data": {
                "labels": ["Info", "Low", "Medium", "High"],
                "data": [
                    vul_totales.vul_tot_info if vul_totales else 0,
                    vul_totales.vul_tot_bajas if vul_totales else 0,
                    vul_totales.vul_tot_medias if vul_totales else 0,
                    vul_totales.vul_tot_altas if vul_totales else 0,
                ]
            },
            "owasp_top_10": {
                "labels": ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'],
                "data": [
                    vul_totales.a01 if vul_totales else 0,
                    vul_totales.a02 if vul_totales else 0,
                    vul_totales.a03 if vul_totales else 0,
                    vul_totales.a04 if vul_totales else 0,
                    vul_totales.a05 if vul_totales else 0,
                    vul_totales.a06 if vul_totales else 0,
                    vul_totales.a07 if vul_totales else 0,
                    vul_totales.a08 if vul_totales else 0,
                    vul_totales.a09 if vul_totales else 0,
                    vul_totales.a10 if vul_totales else 0,]
            }

        }
        return render_template('index.html', data=data)
    except Exception as e:
        logging.error(f"Error al cargar la página principal: {e}")
        return render_template('error.html', message="Error al cargar la página principal."), 500

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """
    Página para iniciar un escaneo.
    """
    form = ScanForm()
    return render_template('scan.html', form=form)

@app.route('/calendar', methods=['GET'])
def calendar():
    """
    Página del calendario de escaneos.
    """
    return render_template('calendar.html')

@app.route('/get_calendar_events', methods=['GET'])
def get_calendar_events():
    """
    Obtiene los eventos del calendario (escaneos completados y programados).
    """
    try:
        today = datetime.now()
        events = []

        # Escaneos completados
        completed_scans = Escaneres_completados.query.filter(Escaneres_completados.fecha_fin <= today).all()
        for scan in completed_scans:
            vulnerabilities = Reportes_vulnerabilidades_url.query.filter(
                Reportes_vulnerabilidades_url.target_url == scan.target_url,
                Reportes_vulnerabilidades_url.fecha_scan == scan.fecha_fin
            ).first()

            events.append({
                "title": f"{scan.target_url}",
                "start": scan.fecha_inicio.strftime('%Y-%m-%d'),
                "end": scan.fecha_fin.strftime('%Y-%m-%d'),
                "backgroundColor": "#28a745",
                "textColor": "#ffffff",
                "type": "completed",
                "vulnerabilities": {
                    "high": vulnerabilities.vul_altas if vulnerabilities else [],
                    "medium": vulnerabilities.vul_medias if vulnerabilities else [],
                    "low": vulnerabilities.vul_bajas if vulnerabilities else [],
                    "info": vulnerabilities.vul_info if vulnerabilities else [],
                }
            })

        # Escaneos programados
        scheduled_scans = Escaneo_programados.query.filter(Escaneo_programados.fecha_programada >= today).all()
        for scan in scheduled_scans:
            events.append({
                "title": f"{scan.target_url}",
                "start": scan.fecha_programada.strftime('%Y-%m-%d'),
                "end": scan.fecha_programada.strftime('%Y-%m-%d'),
                "backgroundColor": "#ffc107",
                "textColor": "#000000",
                "type": "scheduled",
                "details": {
                    "fecha": scan.fecha_programada.strftime('%Y-%m-%d') if scan.fecha_programada else '',
                    "intensidad": scan.intensidad if scan.intensidad else '',
                }
            })

        return jsonify(events)
    except Exception as e:
        logging.error(f"Error al obtener eventos del calendario: {e}")
        return jsonify({'error': 'Error al obtener eventos del calendario.'}), 500
    
@app.route('/process_scan', methods=['POST'])
def process_scan():
    """
    Procesa un escaneo (inmediato o programado).
    """
    try:
        # Obtener datos del formulario
        url = request.form.get('url')
        intensity = request.form.get('intensity')
        email = request.form.get('email')
        scheduled = request.form.get('scheduled', 'false').lower() == 'true'
        dateTime = request.form.get('dateTime')
        #apiScan = request.form.get('apiScan', 'false').lower() == 'true'
        #configFile = request.files.get('file')

        # Validar datos obligatorios
        if not url or not intensity:
            return jsonify({'status': 'error', 'message': 'Faltan datos obligatorios'}), 400

        # Procesar archivo de configuración si existe
        config_data = None
        # if configFile:
        #     try:
        #         config_data = json.loads(configFile.read().decode('utf-8'))
        #     except Exception as e:
        #         logging.error(f"Error al procesar el archivo de configuración: {e}")
        #         return jsonify({'status': 'error', 'message': 'Archivo de configuración inválido.'}), 400

        # Escaneo programado
        if scheduled:
            if not dateTime:
                return jsonify({'status': 'error', 'message': 'La fecha y hora son requeridas para programar el escaneo.'}), 400
            try:
                dateTime_programed = datetime.strptime(dateTime, DATE_FORMAT)
                escaneo_programado = Escaneo_programados(
                    target_url=url,
                    intensidad=intensity,
                    fecha_programada=dateTime_programed,
                    estado="PENDIENTE",
                    email=email,
                    #api_scan=apiScan,
                    #api_file=config_data
                )
                db.session.add(escaneo_programado)
                db.session.commit()
                return jsonify({'status': 'success', 'message': 'Escaneo programado correctamente'}), 200
            except ValueError:
                return jsonify({'status': 'error', 'message': 'Formato de fecha y hora inválido.'}), 400

        # Escaneo inmediato
        zap = connect_to_zap()
        add_url_to_sites(zap, url)
        scan_id = perform_scan(zap, url, intensity)
        send_email(zap, url, email)
        return jsonify({'status': 'success', 'message': f'Escaneo completado con ID {scan_id}'}), 200

    except Exception as e:
        logging.error(f"Error al procesar el escaneo: {e}")
        return jsonify({'status': 'error', 'message': 'Error al procesar el escaneo.'}), 500
    
@app.route('/chatBot', methods=['GET', 'POST'])
def chatBot():
    """
    Página para interactuar con el chatbot.
    """
    form = ChatForm()
    return render_template('chatbot.html', form=form)

@app.route('/context_chatgpt', methods=['POST'])
def interact_with_gpt_context():
    """
    Interactúa con el chatbot basado en LangChain.
    """
    try:
        data = request.get_json()
        prompt = data.get('message')

        if not prompt:
            return jsonify({'error': 'No se proporcionó el mensaje'}), 400

        config = {"configurable": {"thread_id": "1"}}
        events = graph_memory.stream({"messages": [("user", prompt)]}, config, stream_mode="values")

        chatbot_reply = None
        for event in events:
            chatbot_reply = event["messages"][-1].content

        if not chatbot_reply:
            chatbot_reply = "Lo siento, no pude generar una respuesta."

        return jsonify({'reply': chatbot_reply})
    except Exception as e:
        logging.error(f"Error al interactuar con el chatbot: {e}")
        return jsonify({'error': 'Hubo un problema al procesar la solicitud.'}), 500

if __name__ == '__main__':
    init_scheduler_scans()
    app.run(host='0.0.0.0', debug=True, port=5000)  # No usar debug=True en producción
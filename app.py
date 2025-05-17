from dotenv import load_dotenv
load_dotenv()
import os
import json
import logging
from flask import Flask, render_template, request, jsonify,  redirect, url_for, session, flash,  send_from_directory, current_app
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
from forms import ScanForm, ChatForm, FileUploadForm
from langchain import graph_memory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from threading import Thread
from generate_report import remplazar_texto, remplazar_encabezado, modificar_primer_tabla, procesar_alertas, contexto_resumen_ejecutivo
import pytz, time
# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app_logs.log", mode="w", encoding="utf-8")
    ]
)



DB_USER = os.getenv("PSQL_USER")
DB_PASSWORD = os.getenv("PSQL_PASSWORD")
DB_HOST = os.getenv("PSQL_HOST")
DB_PORT = os.getenv("PSQL_PORT")
DB_NAME = os.getenv("DB_NAME") 

# Configuración de la aplicación
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = (f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}') #sqlite:///zap_data_base.db?journal_mode=WAL&timeout=30'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = False


# Configuración de CORS (restringido a dominios específicos)
CORS(app, resources={r"/get_calendar_events": {"origins": "http://localhost"}})

# Inicialización de extensiones
db.init_app(app)
migrate = Migrate(app, db)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000000000 per day", "5000000000 per hour"]
)
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
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

USERNAME = os.getenv('APP_USERNAME', 'admin')
PASSWORD_HASH = os.getenv('APP_PASSWORD', 'password')
#### Rutas ####
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limitar a 5 intentos por minuto
def login():
    """
    Página de inicio de sesión.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == USERNAME and password == PASSWORD_HASH:
            session['logged_in'] = True
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('home'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """
    Cierra la sesión del usuario.
    """
    session.pop('logged_in', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

# Decorador para proteger rutas
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Por favor, inicia sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
@login_required
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
@login_required
def scan():
    """
    Página para iniciar un escaneo.
    """
    form = ScanForm()
    return render_template('scan.html', form=form)

@app.route('/calendar', methods=['GET'])
@login_required
def calendar():
    """
    Página del calendario de escaneos.
    """
    return render_template('calendar.html')

@app.route('/get_calendar_events', methods=['GET'])
@login_required
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
@login_required
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
        

        # Validar datos obligatorios
        if not url or not intensity:
            return jsonify({'status': 'error', 'message': 'Faltan datos obligatorios'}), 400

        # Procesar archivo de configuración si existe
        config_data = None

        # Escaneo programado
        if scheduled:
            if not dateTime:
                return jsonify({'status': 'error', 'message': 'La fecha y hora son requeridas para programar el escaneo.'}), 400
            try:
                madrid_tz = pytz.timezone('Europe/Madrid')
                utc = pytz.UTC
                dateTime_programed = datetime.strptime(dateTime, DATE_FORMAT)
                dateTime_programed = madrid_tz.localize(dateTime_programed)
                dateTime_programed_utc = dateTime_programed.astimezone(utc)
                escaneo_programado = Escaneo_programados(
                    target_url=url,
                    intensidad=intensity,
                    fecha_programada=dateTime_programed_utc,
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
        if not scheduled:
            def run_scan_thread():
                with app.app_context():
                    zap = connect_to_zap()
                    add_url_to_sites(zap, url)
                    perform_scan(zap, url, intensity)
                    send_email(zap, url, email)
                    time.sleep(2)
                    archivos = [
                        "./reportes/grafica_vulnerabilidades.png",
                        "./reportes/custom_report_modificado.docx",
                        "./reportes/alertas.json"
                    ]
                    for fichero in archivos:
                        if os.path.exists(fichero):
                            os.remove(fichero)
                            print(f"Archivo {fichero} eliminado.")
                        else:
                            print(f"El archivo {fichero} no existe.")    

            Thread(target=run_scan_thread).start()

        return jsonify({'status': 'success', 'message': 'Escaneo ejecutándose en segundo plano.'}), 200

    except Exception as e:
        logging.error(f"Error al procesar el escaneo: {e}")
        return jsonify({'status': 'error', 'message': 'Error al procesar el escaneo.'}), 500
    
@app.route('/chatBot', methods=['GET', 'POST'])
@login_required
def chatBot():
    """
    Página para interactuar con el chatbot.
    """
    form = ChatForm()
    return render_template('chatbot.html', form=form)

@app.route('/context_chatgpt', methods=['POST'])
@login_required
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
        print(chatbot_reply, type(chatbot_reply))

        if isinstance(chatbot_reply, list):
            respuesta = "\n".join(str(part).strip() for part in chatbot_reply)
            return jsonify({'reply': respuesta})
        elif isinstance(chatbot_reply, str):
            return jsonify({'reply': chatbot_reply})
    except Exception as e:
        logging.error(f"Error al interactuar con el chatbot: {e}")
        return jsonify({'error': 'Hubo un problema al procesar la solicitud.'}), 500


def generar_reporte_async(json_data, filename):
    from docx import Document
    with app.app_context():
        doc = Document("./reportes/custom_report.docx")
        
        url = json_data['site'][0]['@name']
        alertas = json_data['site'][0]['alerts']

        remplazos = {
            "{nombre-url}": url,
            "{date}": datetime.now().strftime('%d/%m/%Y'),
        }

        remplazar_texto(doc, remplazos)
        remplazar_encabezado(doc, remplazos)
        modificar_primer_tabla(doc, remplazos)
        alertas_set, *_ = procesar_alertas(alertas, url, doc)
        contexto_resumen_ejecutivo(url, alertas_set, url, doc)

        output_path = os.path.join(current_app.root_path, "reportes", filename)
        doc.save(output_path)

@app.route("/upload", methods=["POST", "GET"])
def upload_file():
    form = FileUploadForm()
    if form.validate_on_submit():
        file = form.file.data
        try:
            json_data = json.load(file)
        except json.JSONDecodeError:
            flash("JSON inválido", "danger")
            return render_template('generate_report.html', form=form)
        
        output_filename = f"custom_report_{int(datetime.now().timestamp())}.docx"
        thread = Thread(target=generar_reporte_async, args=(json_data, output_filename))
        thread.start()

        return render_template("procesando.html", filename=output_filename)

    return render_template("generate_report.html", form=form)

@app.route("/reporte_disponible/<filename>")
def reporte_disponible(filename):
    path = os.path.join(current_app.root_path, "reportes", filename)
    if os.path.exists(path):
        return '', 200
    return '', 404

@app.route("/descargar_reporte/<filename>")
def descargar_reporte(filename):
    return send_from_directory(
        directory=os.path.join(current_app.root_path, "reportes"),
        path=filename,
        as_attachment=True,
        mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    )  


@app.route('/scan_progress', methods=['GET'])
@login_required
def progreso():
    try:
        # Obtener el escaneo más reciente que esté en proceso
        scan = Escaneres_completados.query.order_by(Escaneres_completados.fecha_inicio.desc()).first()
        ultimo_escaner = scan.target_url
        proximo = Escaneo_programados.query.filter_by(estado="PENDIENTE").order_by(Escaneo_programados.fecha_programada.asc()).first()
        proximo_escaner = proximo.target_url if proximo else "No hay escaneos programados"
        proximo_fecha = proximo.fecha_programada.isoformat() if proximo else None
        if scan or proximo:
            return jsonify({'progress': scan.progreso,'ultimoScanner': ultimo_escaner, 'proximo': proximo_escaner, 'fecha': proximo_fecha})
        else:
            return jsonify({'progress': 0, 'ultimoScanner': ultimo_escaner, 'proximo': proximo_escaner, 'fecha': proximo_fecha})
    except Exception as e:
        logging.error(f"Error obteniendo el progreso del escaneo: {e}")
        return jsonify({'progress': 0, 'ultimoScanner': "No hay Ultimo Escaner", 'proximo': "No hay Próximo Escaner", 'fecha': 'No hay Fecha'})

init_scheduler_scans()
if __name__ == '__main__':
    #init_scheduler_scans()
    app.run(host='0.0.0.0', debug=True, port=5000)  # No usar debug=True en producción
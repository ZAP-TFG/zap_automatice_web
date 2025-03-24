# from flask import Flask, render_template, request, jsonify
from forms import *
from scanner import connection_to_zap,is_in_sites,active_scan
from werkzeug.utils import secure_filename
import os
from extensions import *
from flask_migrate import Migrate
from datetime import datetime
from openai import OpenAI
import json
from sqlalchemy.inspection import inspect
from sqlalchemy import text
import logging
from schedule_scans import *
import threading
import tiktoken ## contar tokens
from flask_cors import CORS
import importlib

# app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zap_data_base.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
CORS(app, resources={r"/get_calendar_events": {"origins": "http://localhost"}})
# Iniciamos SQLAlchemy
db.init_app(app)
migrate = Migrate(app, db)
from models import *  # Importamos los modelos

def init_sheduler_scans():
    init_scheduler()

#Varibales Gloabales
REPORT_NEW = None
REPORT_OLD = None


@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    vul_totales = Vulnerabilidades_totales.query.first()
    data = {
        "scans_completed": vul_totales.escaneos_totales if vul_totales else 0,
        "total_vulnerabilities": vul_totales.vul_all_totales if vul_totales else 0,
        "chart_data" : {
            "labels" : ["Info","Low", "Medium", "High"],
            "data": [
                vul_totales.vul_tot_info if vul_totales else 0,
                vul_totales.vul_tot_bajas if vul_totales else 0,
                vul_totales.vul_tot_medias if vul_totales else 0,
                vul_totales.vul_tot_altas if vul_totales else 0,
            ]
        }
    }
    return render_template('index.html', data=data)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    form = ScanForm() 
    return render_template('scan.html', form=form)

@app.route('/calendar', methods=['GET'])
def chat_vul():
    return render_template('calendar.html')

@app.route('/get_calendar_events', methods=['GET'])
def get_calendar_events():
    today = datetime.now()
    completed_scans = Escaneres_completados.query.filter(Escaneres_completados.fecha_fin <= today).all()

    events = []
    for scan in completed_scans:
        vulnerabilities_fecha_url = Reportes_vulnerabilidades_url.query.filter(
            Reportes_vulnerabilidades_url.target_url == scan.target_url,
            Reportes_vulnerabilidades_url.fecha_scan == scan.fecha_fin
        ).first()

        events.append({
            "title": f"Completed: {scan.target_url}",
            "start": scan.fecha_inicio.strftime('%Y-%m-%d'),
            "end": scan.fecha_fin.strftime('%Y-%m-%d'),
            "backgroundColor": "#28a745",
            "textColor": "#ffffff",
            "type": "completed",
            "vulnerabilities": {
                "high": vulnerabilities_fecha_url.vul_altas if vulnerabilities_fecha_url and vulnerabilities_fecha_url.vul_altas else [],
                "medium": vulnerabilities_fecha_url.vul_medias if vulnerabilities_fecha_url and vulnerabilities_fecha_url.vul_medias else [],
                "low": vulnerabilities_fecha_url.vul_bajas if vulnerabilities_fecha_url and vulnerabilities_fecha_url.vul_bajas else [],
                "info": vulnerabilities_fecha_url.vul_info if vulnerabilities_fecha_url and vulnerabilities_fecha_url.vul_info else [],
            }
        })

    scheduled_scans = Escaneo_programados.query.filter(Escaneo_programados.fecha_programada >= today).all()
    for scan in scheduled_scans:
        events.append({
            "title": f"Scheduled: {scan.target_url}",
            "start": scan.fecha_programada.strftime('%Y-%m-%d'),
            "end": scan.fecha_programada.strftime('%Y-%m-%d'),
            "backgroundColor": "#ffc107",
            "textColor": "#000000",
            "type": "scheduled",
            "details": {
                "fecha": scan.fecha_programada if scan.fecha_programada else '',
            "intensidad": scan.intensidad if scan.intensidad else '',
                }
        })
    return jsonify(events)




@app.route('/vulnerabilidades', methods=['GET', 'POST'])
def vulnerabilities():
    form = Vulnerabilities()
    return render_template('vulnerabilities.html', form=form)
 
@app.route('/vulnerabilidades_graficas', methods=['POST'])
def vulnerabilidades_charts():
    url = request.form.get('url')
    if not url:
        return jsonify({"error": "URL no proporcionada"}), 400

    # Consulta a la base de datos
    vulnerabilities = Reportes_vulnerabilidades_url.query.filter_by(target_url=url).order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).limit(2).all()

    # Manejo de datos encontrados
    if len(vulnerabilities) == 0:
        return jsonify({"error": "No se encontraron datos para la URL proporcionada"}), 404

    vulnerabilidades_ultima_fecha = vulnerabilities[0]
    vulnerabilidades_fecha_anterior = vulnerabilities[1] if len(vulnerabilities) > 1 else None

    # Gráficos
    data1 = {
        "pieChartNew": {
            "labels": ["Info", "Low", "Medium", "High"],
            "data": [
                vulnerabilidades_ultima_fecha.vul_info if vulnerabilidades_ultima_fecha else 0,
                vulnerabilidades_ultima_fecha.vul_bajas if vulnerabilidades_ultima_fecha else 0,
                vulnerabilidades_ultima_fecha.vul_medias if vulnerabilidades_ultima_fecha else 0,
                vulnerabilidades_ultima_fecha.vul_altas if vulnerabilidades_ultima_fecha else 0,
            ]
        }
    }

    data2 = {
        "pieChartPast": {
            "labels": ["Info", "Low", "Medium", "High"],
            "data": [
                vulnerabilidades_fecha_anterior.vul_info if vulnerabilidades_fecha_anterior else 0,
                vulnerabilidades_fecha_anterior.vul_bajas if vulnerabilidades_fecha_anterior else 0,
                vulnerabilidades_fecha_anterior.vul_medias if vulnerabilidades_fecha_anterior else 0,
                vulnerabilidades_fecha_anterior.vul_altas if vulnerabilidades_fecha_anterior else 0,
            ]
        }
    }

    # Alertas anteriores
    report_json_old = vulnerabilidades_fecha_anterior.report_file if vulnerabilidades_fecha_anterior else {}
    alerts_old = report_json_old.get("site", [])[0].get("alerts", []) if report_json_old else []
    data3 = {
        "alertsOld": [
            {
                "riskdesc": alert.get("riskdesc", "Unknown"),
                "alert": alert.get("alert", "No alert description")
            }
            for alert in alerts_old
        ]
    }

    # Alertas nuevas
    report_json_new = vulnerabilidades_ultima_fecha.report_file if vulnerabilidades_ultima_fecha else {}
    alerts_new = report_json_new.get("site", [])[0].get("alerts", []) if report_json_new else []
    data4 = {
        "alertsNew": [
            {
                "riskdesc": alert.get("riskdesc", "Unknown"),
                "alert": alert.get("alert", "No alert description")
            }
            for alert in alerts_new
        ]
    }

    # Construcción de la respuesta final
    response = {
        "data1": data1,
        "data2": data2,
        "data3": data3,
        "data4": data4
    }
    return jsonify(response)

@app.route('/vulnerabilidades_chatgpt', methods=['POST'])
def obtener_comparativa_vulnerabilidades():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No se proporcionó una URL válida'}), 400

    vulnerabilities = Reportes_vulnerabilidades_url.query.filter_by(target_url=url).order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).limit(2).all()

    if len(vulnerabilities) > 0:
        vulnerabilidades_ultima_fecha = vulnerabilities[0]
        vulnerabilidades_fecha_anterior = vulnerabilities[1] if len(vulnerabilities) > 1 else None
        report_new = vulnerabilidades_ultima_fecha.report_file if vulnerabilidades_ultima_fecha else {}
        report_old = vulnerabilidades_fecha_anterior.report_file if vulnerabilidades_fecha_anterior else {}
        try:
            client = openai_client()
            completion = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "Eres un asistente especializado en vulnerabilidades WEB, donde te van a pasar dos reportes, el primero es el ultimo realizado y el segundo es el anterior. TU objetivo es comparalos y sacar las diferencias entre vulnerabilidades. Y si puedes buscar en internet como mejorarlo, el CVE, OWASP-TOP-10 al que pertenece...Tiene que ser bien estrcuturado y poder ser no muy extenso. Escribelo en markdown bonito y que no haya interliniado entre parrafos ni frases y en español."},
                    {"role": "user", "content": json.dumps(report_new)},
                    {"role": "user", "content": json.dumps(report_old)}
                ]
            )
            response = completion.choices[0].message.content.strip()  # Asegurarse de limpiar espacios innecesarios
            return jsonify({'comparativa': response})
        except Exception as e:
            logging.error(f"Error al interactuar con el LLM: {e}")
            return jsonify({'error': 'Ocurrió un error al procesar los reportes'}), 500
    else:
        return jsonify({'comparativa': 'No se encontraron datos para la URL proporcionada.'})






#def allowed_file(filename):
    """Verifica si el archivo tiene una extensión permitida"""
#    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/process_scan', methods=['POST'])
def process_scan():
    url = request.form.get('url')
    intensity = request.form.get('intensity')
    email = request.form.get('email')
    scheduled = request.form.get('scheduled') == 'true'  
    dateTime = request.form.get('dateTime')  
    apiScan = request.form.get('apiScan') == 'true'  
    configFile = request.form.get('file') 

   
    if not url or not intensity:
        return jsonify({'status': 'error', 'message': 'Faltan datos obligatorios'}), 400

    
    if scheduled:
        if not dateTime:
            return jsonify({'status': 'error', 'message': 'La fecha y hora son requeridas para programar el escaneo.'}), 400
        try:    
            dateTime_programed = datetime.strptime(dateTime, '%Y-%m-%dT%H:%M')
            escaneos_programados = Escaneo_programados(
                target_url = url,
                intensidad = intensity,
                fecha_programada = dateTime_programed,
                estado = "PENDIENTE"
            )
            if configFile:
                try:
                    configFile = json.loads(configFile)
                except json.JSONDecodeError:
                    return jsonify({'status': 'error', 'message': 'El archivo de configuración no es un JSON válido'}), 400
            escaneos_programados.api_file = configFile
            escaneos_programados.api_scan = apiScan
            db.session.add(escaneos_programados)
            db.session.commit()
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Formato de fecha y hora inválido.'}), 400
        
    if configFile:
        try:
            configFile = json.loads(configFile)
        except json.JSONDecodeError:
            return jsonify({'status': 'error', 'message': 'El archivo de configuración no es un JSON válido'}), 400

    if not scheduled:
        try:
            zap = connection_to_zap()
            is_in_sites(zap, url)
            scan_id = active_scan(zap, url, intensity)
            send_email(zap,url,email)
            return jsonify({'status': 'success', 'message': f'Escaneo completado con ID {scan_id}'}), 200
        except Exception as error:
            return jsonify({'status': 'error', 'message': f'Error durante el escaneo: {error}'}), 500

    return jsonify({'status': 'success', 'message': 'Escaneo programado correctamente'}), 200


################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################

####################################################################################################################
#############################                     CLIENTE OPENAI                ####################################
####################################################################################################################
def openai_client():
    openai_key = os.getenv('OPENAI_API_KEY')
    if not openai_key:
        logging.error("Falta openai_key")
        exit(1)
    return OpenAI(api_key=openai_key)


@app.route('/chatBot', methods=['GET'])
def chatbot():
    form = ChatForm()
    return render_template("chatbot.html", form=form)

###################################################################################################################
#############################                       CONTEXTO                  + ####################################
####################################################################################################################

@app.after_request
def after_request(response):
    # Modificaciones del response antes de que se devuelva al cliente
    response.headers['X-Custom-Header'] = 'Value'
    return response

from pruebas_langchain import graph_memory

@app.route('/context_chatgpt', methods=['POST'])
def interact_with_gpt_context(): 
    data = request.get_json()  
    prompt = data.get('message')  

    if not prompt:
        return jsonify({'error': 'No se proporcionó el mensaje'}), 400  

    try:
        # Enviar el mensaje a Langraph y obtener la respuesta
        config = {"configurable": {"thread_id": "1"}}
        events = graph_memory.stream(
            {"messages": [("user", prompt)]}, config, stream_mode="values"
        )

        # Obtener la última respuesta del chatbot
        chatbot_reply = None
        for event in events:
            chatbot_reply = event["messages"][-1].content  # Extraer solo el contenido del mensaje

        if not chatbot_reply:
            chatbot_reply = "Lo siento, no pude generar una respuesta."

        return jsonify({'reply': chatbot_reply})

    except Exception as e:
        logging.error(f"Error al interactuar con el chatbot: {str(e)}")
        return jsonify({'error': 'Hubo un problema al procesar la solicitud.'}), 500  



def count_tokens(promt):
    Model = "gpt-3.5-turbo"
    tokenizer = tiktoken.encoding_for_model(Model)
    tokens = tokenizer.encode(promt)
    return len(tokens)


###################################################################################################################
#############################                       RESPUESTA FRONT                 + ####################################
####################################################################################################################


###################################################################################################################
#############################                       CONFIGURACION                 + ####################################
####################################################################################################################
def lanzar_escaneo(url,intensidad):
    with app.app_context():
        zap = connection_to_zap()
        is_in_sites(zap, url)
        scan_id = active_scan(zap, url, intensidad)
        email = 'gabriel.izquierdo.gonzalez@gmail.com'
        send_email(zap,url,email)

def configuracion_chat(message):
    client = openai_client()
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistento al que le van a pasar una configuracion y tu tienes que sacar solo la url, la fecha en formato Datetime y la intesidad(en ingles). Cuando te digan que el escaner lo quieres para ahora tiene que poner en fecha: now. sacamelo en formato JSON sin ```json. solo el JSON"},
                { "role": "user", "content": message}
            ]
        )
        print(response.choices[0].message.content)
        data = json.loads(response.choices[0].message.content)
        url = data['url']
        intensidad = data['intensidad']
        fecha = data['fecha']

        print(url,intensidad,fecha)
        if fecha == 'now':
            try:
                thread = threading.Thread(target=lanzar_escaneo, args=(url,intensidad))
                thread.start()
                return jsonify({"reply": "Escaneo lanzado correctamente, seras notificado por email"})
            except Exception as error:
                return jsonify({"reply": "El escaneo no se lanzo correctamente pruebe otra vez"})
        #return jsonify({"reply": response.choices[0].message.content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



if __name__ == '__main__':
    init_sheduler_scans()
    app.run(debug=True)

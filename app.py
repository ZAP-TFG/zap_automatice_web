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






def allowed_file(filename):
    """Verifica si el archivo tiene una extensión permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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


# variables globales
PROMT = None

@app.route('/context_chatgpt', methods=['POST'])
def interact_with_gpt_context():
    data = request.get_json()  # Obtienes los datos del JSON enviado en la solicitud POST
    prompt = data.get('message')  # El mensaje del usuario

    if not prompt:
        return jsonify({'error': 'No se proporcionó el mensaje'}), 400  # Validar que haya un mensaje

    try:
        # Crear el cliente OpenAI
        client = openai_client()

        # Llamada a la API de OpenAI para generar la respuesta
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": """  
                #OBJETIVOS
                 Eres un asistente especializado en sacar el contexto de lo que te están pidiendo y experto en ciberseguridad. La salida será un JSON.
                 Tendrás que sacar un porcentaje de pertenencia a cada categoría.
                 - configuracion: Cuando te pidan configurar o programar un escáner 
                 - historial: ¿Qué hay de nuevo respecto ayer?' o 'hay algun escaner nuevo'.
                 - preguntas: Cuando te pidan preguntas de cualquier ámbito.
                 - reportes: Cuando te pidan datos sobre una url.
                 - comparacion: cuando te pidan comparar reportes
                 - vulnerabilidades: cuando te pidan vulnerabilidades generales sobre urls o en cuantas urls hay dicha vulnerabilidad o alerta
                 - generar_reporte: cuando te pidan explicitamente generar un reporte en el formato deseado
                 - consulta_sql: cuando te pidan modificar un tabla con los valores deseados. 
                Posibles contextos: configuracion, reportes, preguntas, historial, comparacion, vulnerabilidades, generar_reporte, consulta_sql
                - input del usuario: Como solventarias la vulenrabilidad de falta de token anti-CRSF
                 respuesta:{"contexto": {"configuracion":0,
                  "historial":0,  
                 "preguntas":1,
                 "reportes":0,
                 "comparacion":0,
                 "vulnerabilidades":0,
                 "generar_reporte": 0,
                 "consulta_sql": 0
                 } ,
                  "message": "copia y pega el mensaje del usuario"
                 }
                - input del usuario: Que hay de nuevo respecto ayer o algun escaner ejecutandose? o Programacion de escaneres para hoy? o cuantos escaneres hemos ejecutado en esta semana?
                 respuesta:{"contexto": {"configuracion":0,
                  "historial":1,  
                 "preguntas":0,
                 "reportes":0,
                 "comparacion":0,
                 "vulnerabilidades":0,
                 "generar_reporte": 0,
                 "consulta_sql": 0} ,
                  "message": "Que hay de nuevo respecto ayer"
                 }
                - input del usuario: dame las ultimas vulnerabilidades de http://example.com o cuantas vulnerabilidades tiene http://example.com
                 respuesta:{"contexto": {"configuracion":0,
                  "historial":0,  
                 "preguntas":0,
                 "reportes":1,
                 "comparacion":0,
                 "vulnerabilidades":0,
                 "generar_reporte": 0,
                 "consulta_sql": 0} ,
                  "message": "copia y pega el mensaje del usuario"
                 }
                - input del usuario: programame un escaner para http://example.com con intesidad media para el 17 de enero de 2025 a las 12pm
                 respuesta:{"contexto": {"configuracion":1,
                  "historial":0,  
                 "preguntas":0,
                 "reportes":0,
                 "comparacion":0,
                 "vulnerabilidades":0,
                 "generar_reporte": 0,
                 "consulta_sql": 0} ,
                  "message": "copia y pega el mensaje del usuario"
                 - input del usuario: comparame los ultimos dos reportes de http://example.com o que diferencias hay entre los ultimos reportes de http://example.com
                 respuesta:{"contexto": {"configuracion":0,
                  "historial":0,  
                 "preguntas":0,
                 "reportes":0,
                 "comparacion":1,
                 "vulnerabilidades":0,
                 "generar_reporte": 0,
                 "consulta_sql": 0} ,
                  "message": "copia y pega el mensaje del usuario"
                 - input del usuario: en que url tenemos XSS o en que escaneres hemos encontrado CSRF o cuantas urls tenemos donde tengan vulnerabildades altas
                 respuesta:{"contexto": {"configuracion":0,
                  "historial":0,  
                 "preguntas":0,
                 "reportes":0,
                 "comparacion":0,
                 "vulnerabilidades":1,
                 "generar_reporte": 0,
                 "consulta_sql": 0} ,
                  "message": "copia y pega el mensaje del usuario"
                 - input del usuario: generame el reporte en formate pdf para http://example.com o puedes generarme un reporte para http://example en formato JSON o enviame por correo el ultimo reporte de http://example.com
                 respuesta:{"contexto": {"configuracion":0,
                  "historial":0,  
                 "preguntas":0,
                 "reportes":0,
                 "comparacion":0,
                 "vulnerabilidades":0,
                 "generar_reporte": 1,
                 "consulta_sql": 0} ,
                  "message": "http://example.com"
                 }
                  - input del usuario: quiero que cambies en la tabla periocidad la periocidad de http://example.com a cada 15 dias o puedes añadir estas urls con su periocidad a la bbdd?
                 respuesta:{"contexto": {"configuracion":0,
                  "historial":0,  
                 "preguntas":0,
                 "reportes":0,
                 "comparacion":0,
                 "vulnerabilidades":0,
                 "generar_reporte": 0,
                 "consulta_sql": 1} ,
                  "message": "copia y pega el mensaje del usuario"
                 }
                
                """},
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        return jsonify({'reply': completion.choices[0].message.content})

    except Exception as e:
        logging.error(f"Error al interactuar con el LLM: {str(e)}")
        return jsonify({'error': 'Hubo un problema al procesar la solicitud.'}), 500


def count_tokens(promt):
    Model = "gpt-3.5-turbo"
    tokenizer = tiktoken.encoding_for_model(Model)
    tokens = tokenizer.encode(promt)
    return len(tokens)


###################################################################################################################
#############################                       RESPUESTA FRONT                 + ####################################
####################################################################################################################


@app.route('/respuesta_chatgpt', methods=['POST'])
def respuesta_chatgpt():
    data = request.get_json()
    print("Datos recibidos:", data)
    context = data.get('contexto')
    message = data.get('message')

    if not context or not message:
        return jsonify({'reply':"Faltan 'contexto' o 'message' en los datos"}), 400
    elif float(context.get('preguntas')) > 0.7:
        return general_chat(message)
    if float(context.get('configuracion')) > 0.7:
        return configuracion_chat(message)
    elif float(context.get('comparacion')) > 0.7:
       return comparacion(message)
    elif float(context.get('vulnerabilidades')) > 0.7:
        return reportes_vulnerabilidades(message)
    elif float(context.get('reportes')) > 0.7:
        return reportes_vulnerabilidades(message)
    elif float(context.get('historial')) > 0.7:
        return historial(message)
    elif float(context.get('consulta_sql')) > 0.7:
        return general_chat(message)
    else:
        return jsonify({"error": "Contexto desconocido"}), 400


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


###################################################################################################################
#############################                       PREGUNTAS GENERALES                  ####################################
####################################################################################################################
def general_chat(message):
    client = openai_client()
    try:
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": """  
                #Role
                Eres un asistente especializado en el area de ciberseguridad. Te haran preguntas y tendras que responder la manera mas clara 
                y precisa posible. La salida sera en formato markdown.
                """},
                { "role": "user", "content": message}
            ]
        )
        return jsonify({"reply": response.choices[0].message.content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


###################################################################################################################
#############################                   CONSULTAS GENERALES            ####################################
####################################################################################################################

def consultas_generales(message):
    client = openai_client()
    now = datetime.now()
    try:
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": f"""  
                Eres un experto en generación de sentencias SQL. Te entrego la siguiente información sobre la base de datos (SQLite) y,
                a continuación, te haré una pregunta en lenguaje natural. Responde únicamente con una sentencia SQL válida.
                Base de datos (SQLite).( LA SALIDA TIENE QUE SER SIN ```sql POR FAVOR. Tablas y columnas:

                    Tabla: escaneos_completados
                        - id (Integer, primary_key)
                        - target_url (String(200))
                        - estado (String(50))
                        - fecha_inicio (DateTime)
                        - fecha_fin (DateTime)
                        - intensidad (String(50))
                        - api_scan (Boolean)
                        - api_file (JSON)
                        - report_file (JSON)

                    Tabla: reportes_vulnerabilidades_url
                        - id (Integer, primary_key)
                        - target_url (String(200))
                        - vul_altas (JSON)
                        - vul_medias (JSON)
                        - vul_bajas (JSON)
                        - vul_info (JSON)
                        - fecha_scan (DateTime)
                        - report_file (JSON)

                    Tabla: escaneos_programados
                        - id (Integer, primary_key)
                        - target_url (String(200))
                        - intensidad (String(50))
                        - fecha_programada (DateTime)
                        - estado (String(50)) ('PENDIENTE' o 'COMPLETADO')
                        - archivo_subido (String(200))
                        - api_scan (Boolean)
                        - api_file (JSON)
                        - periodicidad_dias (Integer)
                    Recuerda que la fecha actual es: {now}, y debes tenerlo en cuenta para cualquier filtrado de fecha que se solicite.
                    ####EJEMPLOS:
                    -  Comparame los últimos reportes de http://example.com
                        Esta petición requiere consultar la tabla reportes_vulnerabilidades_url y extraer únicamente los dos reportes más recientes relacionados con target_url = 'http://example.com', devolviendo, por ejemplo, los campos del reporte (en concreto report_file si fuera necesario).
                        Ejemplo de respuesta (solo SQL):
                            SELECT report_file
                            FROM reportes_vulnerabilidades_url
                            WHERE target_url = 'http://example.com'
                            ORDER BY fecha_scan DESC
                            LIMIT 2;
                    -  Resumeme el penultimo reporte de http://example.com
                        Esta petición requiere consultar la tabla reportes_vulnerabilidades_url y extraer únicamente los dos reportes más recientes relacionados con target_url = 'http://example.com', devolviendo, por ejemplo, los campos del reporte (en concreto report_file si fuera necesario).
                        Ejemplo de respuesta (solo SQL):
                            SELECT report_file
                            FROM reportes_vulnerabilidades_url
                            WHERE target_url = 'http://example.com'
                            ORDER BY fecha_scan DESC
                            LIMIT 1 OFFSET 1;
                    -  Qué vulnerabilidades tiene la url http://example.com
                        El objetivo es filtrar por vul_altas, vul_medias, vul_bajas, etc., sacando la información del último escaneo (ordenado por fecha_scan descendente y tomando el primero).
                        Ejemplo de respuesta (solo SQL):
                        SELECT vul_altas, vul_medias, vul_bajas, vul_info
                            FROM reportes_vulnerabilidades_url
                            WHERE target_url = 'http://example.com'
                            ORDER BY fecha_scan DESC
                            LIMIT 1;
                    -  Qué URLs tienen la vulnerabilidad XSS o algo parecido
                        Hay que buscar entradas en reportes_vulnerabilidades_url que contengan términos como 'XSS' o variantes en los campos de vulnerabilidades (posiblemente vul_altas, vul_medias, vul_bajas, vul_info). Dependiendo de cómo se almacenen estos JSON, la consulta puede variar.
                        Ejemplo de respuesta (solo SQL):
                            SELECT target_url
                            FROM reportes_vulnerabilidades_url
                            WHERE (vul_altas LIKE '%XSS%'
                            OR vul_altas LIKE '%XSS refle%'
                            OR vul_medias LIKE '%XSS%'
                            OR vul_bajas LIKE '%XSS%'
                            OR vul_info LIKE '%XSS%');
                    -  Qué escáneres hay programados para hoy
                        Se debe consultar la tabla escaneos_programados y filtrar por la fecha que coincida con el día actual.
                        Ejemplo de respuesta (solo SQL): 
                            SELECT *
                            FROM escaneos_programados
                            WHERE DATE(fecha_programada) = DATE('now');
                    - Qué hay de nuevo respecto a ayer
                        Consultar la tabla escaneos_completados para ver si se ejecutó algún escáner hoy o si se ejecutó alguno respecto a ayer. Aquí podríamos comparar la fecha fecha_fin con la de ayer.
                        Ejemplo de respuesta (solo SQL):
                            SELECT *
                            FROM escaneos_completados
                            WHERE DATE(fecha_fin) >= DATE('now', '-1 day')
                            ORDER BY fecha_fin DESC;
                 """},
                {"role": "user","content": message},
            ],
            temperature=0.8
        )
        return (completion.choices[0].message.content)
    except Exception as e:
        logging.error(f"Error en la consulta consultas_generales al GPT: {e}")


###################################################################################################################
#############################            CONSULTAS GENERALES-COMPARACION       ####################################
####################################################################################################################

def comparacion(message):
    try:
        client = openai_client()
        time.sleep(0.5)
        
        # Generar la consulta
        response = consultas_generales(message)
        query = text(response)
        print("Query generado:", query)
        
        # Ejecutar la consulta en la base de datos
        result = db.session.execute(query).fetchall()
        print("Resultados crudos de la BD:", result)
        
        # Convertir los resultados en JSON
        consulta_bbdd = [dict(row._mapping) for row in result]
        json_data = json.dumps(consulta_bbdd, indent=4)
        lista_json_data = json.loads(json_data)

        ultimo_reporte = lista_json_data[0]
        anterior_reporte = lista_json_data[1]


        # # Truncar datos si exceden el límite de tokens
        # def truncate_json_data(json_data, max_tokens=8000):
        #     lines = json_data.splitlines()
        #     truncated = []
        #     token_count = 0

        #     for line in lines:
        #         token_count += len(line.split())
        #         if token_count > max_tokens:
        #             break
        #         truncated.append(line)

        #     return "\n".join(truncated)

        # truncated_json_data = truncate_json_data(json_data, max_tokens=7000)

        # Preparar los mensajes para el modelo
        messages = [
            {
                "role": "system",
                "content": """  
                Eres un experto en ciberseguridad especializado en análisis y comparación de reportes de vulnerabilidades.Se te proporcionarán dos reportes generados por una herramienta de análisis de vulnerabilidades (como ZAPROXY):
                Primer reporte (anterior): Refleja el estado inicial, antes de aplicar mejoras.
                Segundo reporte (nuevo): Refleja el estado después de aplicar medidas correctivas.
                Tu tarea será analizar y comparar ambos reportes para identificar mejoras, áreas críticas y tendencias generales de seguridad.
                EJEMPLO:
                ### Comparación de Reportes de Vulnerabilidades

                    #### Resumen General
                    Se observa una **mejora general** en el estado de seguridad, con una reducción en vulnerabilidades críticas y la resolución de varias vulnerabilidades altas. Sin embargo, persisten algunas áreas de preocupación debido a la aparición de nuevas vulnerabilidades de alta severidad.

                    ---

                    #### Vulnerabilidades Resueltas
                    1. **[Nombre de la Vulnerabilidad]**
                    - **Nivel de criticidad anterior:** Alto
                    - **URL afectada:** [URL específica]
                    - **Descripción:** Resuelta mediante [acción correctiva aplicada].

                    2. **[...]**

                    ---

                    #### Vulnerabilidades Persistentes
                    1. **[Nombre de la Vulnerabilidad]**
                    - **Nivel de criticidad:** Alto (sin cambios)
                    - **URL afectada:** [URL específica]
                    - **Estado:** Persistente debido a [razón, p. ej., complejidad para solucionar].

                    2. **[...]**

                    ---

                    #### Mejoras Significativas
                    1. Resolución de 3 vulnerabilidades críticas relacionadas con [descripción breve, p. ej., inyección SQL].
                    2. Implementación de políticas de seguridad de contenido (CSP) que mitigaron [problemas específicos].

                    ---

                    #### Áreas de Preocupación
                    1. **Nueva vulnerabilidad crítica:**
                    - **Nombre:** [Descripción breve]
                    - **Impacto:** Alta criticidad en [URL afectada].
                    - **Acción sugerida:** Revisar la implementación de [área específica].

                    2. Persistencia de vulnerabilidades de alta criticidad en [URL o funcionalidad].

                    ---

                    #### Conclusión
                    El análisis demuestra un progreso claro, con una reducción significativa en las vulnerabilidades críticas y altas. Sin embargo, persisten áreas de riesgo que requieren atención inmediata, especialmente en [categorías específicas]. Se recomienda priorizar estas mejoras en las siguientes fases de desarrollo.
                """
            },
            {
                "role": "user",
                "content": f"Primer reporte: {anterior_reporte}"
            },
            {
                "role": "user",
                "content": f"Segundo reporte: {ultimo_reporte}"
            }
        ]

        # Enviar la solicitud al modelo
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=messages,
            temperature=0.7
        )

        # Devolver la respuesta generada
        return jsonify({"reply": completion.choices[0].message.content})

    except Exception as e:
        logging.error(f"Error en la función comparacion: {e}")
        return jsonify({"error": f"Ocurrió un error: {str(e)}"}), 500


###################################################################################################################
#############################            CONSULTAS GENERALES-REPORTES_VULNERABILIDADES       ####################################
####################################################################################################################

def reportes_vulnerabilidades(message):
    client = openai_client()
    time.sleep(0.5)
    response = consultas_generales(message)
    query = text(response)
    print("Query generado:", query)
    result = db.session.execute(query).fetchall()
    print("Resultados crudos de la BD:", result)
    consulta_bbdd = [dict(row._mapping) for row in result]
    json_data = json.dumps(consulta_bbdd, indent=4)
    print(json_data)
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": """  
                Rol: Eres un experto en ciberseguridad. Se te proporcionarán vulnerabilidades detectadas, las URLs en las que se han encontrado, el CWE correspondiente y la categoría OWASP Top 10 aplicable. Dependiendo de la petición del usuario, deberás:
                Solo listar vulnerabilidades
                Si el usuario pregunta (por ejemplo): “Qué vulnerabilidades tiene la URL <URL>?”
                Acción: Responder únicamente con la lista de vulnerabilidades en formato Markdown, sin explicaciones.
                Listar y explicar vulnerabilidades
                Si el usuario pregunta (por ejemplo): “Explícame las vulnerabilidades que tiene la URL <URL>.”
                Acción: Responder con la lista de vulnerabilidades y una explicación breve de cada una, también en formato Markdown.
                Resumen de un reporte
                Si el usuario pide un resumen (por ejemplo): “Resumeme el ultimo reporte https://example.com”
                Acción: Sacar vulnerabilidades segun criticidad, sin repeticiones de url y Encontrar falsos positivos basandote en la confianza y parametros como "attack", "evidence" y "otherinfo"
                Formato Markdown
                Siguiendo las pautas recomendadas para la creación de reportes de seguridad, cada respuesta deberá entregarse en un formato Markdown sencillo, por ejemplo:
                Listas con guiones o numeradas.
                Uso de negritas o itálicas cuando corresponda.
                Agrupación de vulnerabilidades según sea necesario.
                (Para más información sobre la creación de reportes en formato Markdown, puedes consultar 14.)
                Ejemplos
                - Caso 1: Solo listar vulnerabilidades
                Usuario:
                “¿Qué vulnerabilidades tiene la URL http://example.com?”
                Tu respuesta (solo listado en Markdown):
                    - SQL Injection
                    - Broken Access Control
                    - Cross-Site Scripting (XSS)
                (Sin explicación adicional.)
                Caso 2: Listar y explicar vulnerabilidades
                Usuario:
                “Explícame las vulnerabilidades que tiene la URL http://example.com.”
                Tu respuesta (listado + explicación en Markdown):
                    1. **SQL Injection**  
                    Permite a un atacante inyectar sentencias SQL maliciosas para leer o modificar datos sin autorización.

                    2. **Broken Access Control**  
                    Se produce cuando las restricciones de acceso no se aplican correctamente, lo que permite a atacantes acceder o modificar recursos a los que no deberían tener acceso.

                    3. **Cross-Site Scripting (XSS)**  
                Posibilita inyectar código JavaScript malicioso en páginas vistas por otros usuarios, comprometiendo su sesión o datos.
                - Caso 3: Resumen de un reporte
                Usuario:
                “Resumeme el ultimo reporte de https://example.com”
                Tu respuesta estara formada por dos partes:
                 1. La parte de todas las vulnerabilidades segun criticidad, sin repeticiones de url
                 2. Encontrar falsos positivos basandote en la confianza y parametros como "attack", "evidence" y "otherinfo"
                
                """},
                {
                    "role": "user",
                    "content": message
                },
                {
                    "role": "user",
                    "content": json_data
                }
            ],
            temperature=0.8
        )
        return jsonify({"reply": completion.choices[0].message.content})
    except Exception as e:
        logging.error(f"Error en reportes_vulnerabilidades_2 del GPT: {e}")
        return jsonify({"error en reportes_vulnerabilidades": str(e)}), 500


###################################################################################################################
#############################            CONSULTAS GENERALES-REPORTES_VULNERABILIDADES       ####################################
####################################################################################################################

def historial(message):
    now = datetime.now()
    client = openai_client()
    time.sleep(0.5)
    response = consultas_generales(message)
    query = text(response)
    print("Query generado:", query)
    result = db.session.execute(query).fetchall()
    print("Resultados crudos de la BD:", result)
    consulta_bbdd = [dict(row._mapping) for row in result]
    json_data = json.dumps(consulta_bbdd, indent=4)
    print(json_data)
    try:
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": f"""  
                Rol: Eres un experto en filtracion de datos. Al que le van a pasar los datos de una bbdd y tendra qeu filtrar por fecha 
                actual de hoy que es {now}. Tendras que sacar la fecha y la url de la tabla. Y siempre enformato markdown.
                En caso que se te proporcione algo vacio o no se te proporcione ningun dato significara que no hay datos por tanto sera wur no habra escaneres que se hayan ejecutado o que se vayan a ejecutar.
                -Posibles ejemplos:
                1. input user: que hay de nuevo respecto ayer?
                Tendras que utlizar la fecha de hoy y ver que escaneres se han ejecutado el dia anterior. Tendras que sacar la url y la la hora a la que se ejecuto.
                2. input user: escaneres programados para hoy? o que escaneres tocan hoy? o proximos escaneres?
                Tendras que sacar la url y la hora a la que se van a ejecutar esos escaneres. 
                """},
                {
                    "role": "user",
                    "content": message
                },
                {
                    "role": "user",
                    "content": json_data
                }
            ],
            temperature=0.4
        )
        return jsonify({"reply": completion.choices[0].message.content})
    except Exception as e:
        logging.error(f"Error en reportes_vulnerabilidades_2 del GPT: {e}")
        return jsonify({"error en reportes_vulnerabilidades": str(e)}), 500

# def vulnerabilidades_chat(message):
#     client = openai_client()
#     query = Reportes_vulnerabilidades_url.query.filter_by(target_url=message).order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).first()
#     report = json.dumps(query.report_file)
#     try:
#         response = client.chat.completions.create(
#             model="gpt-3.5-turbo",
#             messages=[
#                 {"role": "system", "content": """##### OBJETIVOS
#                                                         Eres un asistetne especilizado en ciberseguridad. Al que le van a pasar un reporte en formato JSON de una url 
#                                                         y vas a tener que decir las vulnerabilidades que tiene y su creticidad.No quiero descricciones. Sacme el resultado en formato markdown.
#                                                 #### EJEMPLO en markdown:
#                                                     '''
#                                                     ###Vulenrabilidades
#                                                   - Missing Anti-Clickjacking Header -> MEDIA
#                                                   - Content Security Policy (CSP) Header Not Set -> MEDIA'''
#                                                 """},
#                 { "role": "user", "content": report}
#             ]
#         )
#         PROMT = PROMT + response.choices[0].message.content
#         return jsonify({"reply": response.choices[0].message.content})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################
################################################################################################################################################################
# @app.route('/chatget', methods=['POST'])
# def chatget():
#     client = openai_client()
#     user_message = request.json.get('message')
#     try:
#         response = client.chat.completions.create(
#             model="gpt-3.5-turbo",
#             messages=[
#                 {"role": "system", "content": "Eres un asistente experto en vulnerabilidades web"},
#                 { "role": "user", "content": user_message}
#             ]
#         )
#         return jsonify({"reply": response.choices[0].message.content})
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

# @app.route('/chatconfig', methods=['POST'])
# def chatconfig():
#     client = openai_client()
#     user_message = request.json.get('message')
#     try:
#         response = client.chat.completions.create(
#             model="gpt-3.5-turbo",
#             messages=[
#                 {"role": "system", "content": "Eres un asistento al que le van a pasar una configuracion y tu tienes que sacar solo la url, la fecha en formato Datetime y la intesidad, sacamelo en formato JSON"},
#                 { "role": "user", "content": user_message}
#             ]
#         )
#         return jsonify({"reply": response.choices[0].message.content})
#     except Exception as e:
#         logging.error("error al comunicarse con la api")
#         exit(1)

# @app.route('/api/vulnerabilidaes', methods=['POST'])
# def chat_sql():
#     client = openai_client()
#     user_message = request.json.get('message')
#     inspector = inspect(db.engine)
#     columnas = inspector.get_columns("reportes_vulnerabilidades_url")

#     try:
#         # Interactuar con OpenAI para obtener la consulta SQL
#         response = client.chat.completions.create(
#             model="gpt-4-turbo",
#             messages=[
#                 {"role": "system", "content": "Eres un asistente especializado en consultas SQL al que le voy a pasar la informacion de la tabla de la bbdd para que pueda realizar su consulta saviendo que la tabla se llama reportes_vulnerabilidades_url. Las vulnerabilidades se encuentran en el report_file. Solo quiero la consulta, no quiero explicaiones ni que pongas ```sql "},
#                 {"role": "system", "content": f"{columnas}"},
#                 {"role": "user", "content": user_message}
#             ]
#         )
        
#         if not response or not response.choices or not response.choices[0].message.content:
#             raise ValueError("Respuesta inválida o incompleta de OpenAI")
        
#         sql_query = response.choices[0].message.content
#         if not sql_query.lower().startswith("select"):
#             raise ValueError(f"Consulta SQL inválida: {sql_query}")

        
#         query = text(sql_query)
#         try:
#             resultados = db.session.execute(query).fetchall()
#         except Exception as e:
#             logging.error(f"Error al ejecutar la consulta SQL: {e}")
#             return jsonify({"error": "Error en la consulta SQL.", "details": str(e)}), 400

        
#         try:
#             report_file = [json.loads(fila[0]) for fila in resultados]
#         except json.JSONDecodeError as e:
#             logging.error(f"Error al decodificar JSON: {e}")
#             return jsonify({"error": "Error al procesar resultados.", "details": str(e)}), 500

#         json_file = json.dumps(report_file, indent=4)
#         response2 = chat_resum_vul(client, json_file)

#         # Continuar con el resto de la lógica
#         # url = None
#         # for fila in report_file:
#         #     if 'site' in fila:
#         #         for site in fila['site']:
#         #             if '@name' in site:
#         #                 url = site['@name']
#         #     if url:
#         #         break

#         # vul_urls = Reportes_vulnerabilidades_url.query.filter_by(target_url=url).order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).limit(len(json_file)).all()
#         # data = {
#         #     "chart_data": {
#         #         "labels": ["Info", "Low", "Medium", "High"],
#         #         "data_first_row": [
#         #             vul_urls[0].vul_altas if len(vul_urls) > 0 else 0,
#         #             vul_urls[0].vul_medias if len(vul_urls) > 0 else 0,
#         #             vul_urls[0].vul_bajas if len(vul_urls) > 0 else 0,
#         #             vul_urls[0].vul_info if len(vul_urls) > 0 else 0,
#         #         ],
#         #         "data_second_row": [
#         #             vul_urls[1].vul_altas if len(vul_urls) > 1 else 0,
#         #             vul_urls[1].vul_medias if len(vul_urls) > 1 else 0,
#         #             vul_urls[1].vul_bajas if len(vul_urls) > 1 else 0,
#         #             vul_urls[1].vul_info if len(vul_urls) > 1 else 0,
#         #         ]
#         #     }
#         # }
#         return jsonify({"reply": response2})

#     except Exception as e:
#         logging.error(f"Error al comunicarse con la API: {e}")
#         return jsonify({"error": "Ocurrió un error en el servidor.", "details": str(e)}), 500


# def chat_resum_vul(client, bbdd_data):
#     try:

#         completion = client.chat.completions.create(
#             model="gpt-4-turbo",
#             messages=[
#                 {"role": "system", "content": "Eres un asistente especializado en vulnerabilidades WEB al que le van a pasar uno o dos reportes y lo mas resumido posible sacar las diferencias. Bien estructurado y que sea corto"},
#                 {
#                     "role": "user",
#                     "content": bbdd_data
#                 }
#             ]
#         )
#         return completion.choices[0].message.content
#     except Exception as e:
#         logging.error(f"Error al interactuar con el LLM")

if __name__ == '__main__':
    init_sheduler_scans()
    app.run(debug=True)

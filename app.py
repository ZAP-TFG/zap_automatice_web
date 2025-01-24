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

# app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///zap_data_base.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
UPLOAD_FOLDER = 'documents_api' 
ALLOWED_EXTENSIONS = {'json', 'yaml'}  
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
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

@app.route('/reports', methods=['GET', 'POST'])
def chat_vul():
    form = ChatForm()
    return render_template('reports.html', form=form)

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
                 - historial: ¿Qué hay de nuevo respecto ayer?' o 'hay algun escaner nuevo'
                 - preguntas: Cuando te pidan preguntas de cualquier ámbito.
                 - reportes: Cuando te pidan datos sobre una url.
                 ### OUTPUT FORMATO DE SALIDA
                 {"contexto": {'configuracion': Probabilidad de que pertenezca a la categoria configuracion,
                  'historial': Probabilidad de que pertenezca a la categoria historial,  
                 'preguntas': Probabilidad de que pertenezca a la categoria preguntas,
                 'reportes': Probabilidad de que pertenezca a la categoria reportes} ,
                  "message": "copiar y pegar el mensage del usuario"
                 ##EJEMPLOS
                 3.  (ejemplo: "Como solventarias la vulenrabilidad de falta de token anti-CRSF", "que tiempo hace hoy", "dame los reportes del banco mundial", "como solvento la vulnerabilidad 'x' de esta url."): preguntas.
                4. Cuando te pidan datos sobre una url será: reportes.
                Posibles contextos: configuracion, reportes, preguntas, historial.
                - input del usuario: Como solventarias la vulenrabilidad de falta de token anti-CRSF
                 respuesta:{"contexto": {'configuracion':0,
                  'historial':0,  
                 'preguntas':1,
                 'reportes':0} ,
                  "message": 'Como solventarias la vulenrabilidad de falta de token anti-CRSF'
                 }
                - input del usuario: Que hay de nuevo respecto ayer
                 respuesta:{"contexto": {'configuracion':0,
                  'historial':1,  
                 'preguntas':0,
                 'reportes':0} ,
                  "message": 'Que hay de nuevo respecto ayer'
                 }
                - input del usuario: dame las ultimas vulnerabilidades de http://example.com
                 respuesta:{"contexto": {'configuracion':0,
                  'historial':0,  
                 'preguntas':0,
                 'reportes':1} ,
                  "message": 'http://example.com'(solo quiero la URL)
                 }
                - input del usuario: programame un escaner para http://example.com con intesidad media para el 17 de enero de 2025 a las 12pm
                 respuesta:{"contexto": {'configuracion':1,
                  'historial':0,  
                 'preguntas':0,
                 'reportes':0} ,
                  "message": 'programame un escaner para http://example.com con intesidad media para el 17 de enero de 2025 a las 12pm'
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


@app.route('/respuesta_chatgpt', methods=['POST'])
def respuesta_chatgpt():
    data = request.get_json()
    print("Datos recibidos:", data)
    context = data.get('contexto')
    message = data.get('message')
    if not context or not message:
        return jsonify({'reply':"Faltan 'contexto' o 'message' en los datos"}), 400
    if float(context.get('configuracion')) > 0.7:
        return configuracion_chat(message)
    elif float(context.get('reportes')) > 0.7:
       return vulnerabilidades_chat(message)
    elif float(context.get('historial')) > 0.7:
        return jsonify({'reply': context})
    elif float(context.get('preguntas')) > 0.7:
        return general_chat(message)
    else:
        return jsonify({"error": "Contexto desconocido"}), 400

##########################################################################################
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

############################################################################33
def general_chat(message):
    client = openai_client()
    try:
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente al que le van a preguntar cualquier cosa y tienes que responder de la manera mas profesional posible"},
                { "role": "user", "content": message}
            ]
        )
        PROMT = PROMT + response.choices[0].message.content
        return jsonify({"reply": response.choices[0].message.content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def vulnerabilidades_chat(message):
    client = openai_client()
    query = Reportes_vulnerabilidades_url.query.filter_by(target_url=message).order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).first()
    report = json.dumps(query.report_file)
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": """##### OBJETIVOS
                                                        Eres un asistetne especilizado en ciberseguridad. Al que le van a pasar un reporte en formato JSON de una url 
                                                        y vas a tener que decir las vulnerabilidades que tiene y su creticidad.No quiero descricciones. Sacme el resultado en formato markdown.
                                                #### EJEMPLO en markdown:
                                                    '''
                                                    ###Vulenrabilidades
                                                  - Missing Anti-Clickjacking Header -> MEDIA
                                                  - Content Security Policy (CSP) Header Not Set -> MEDIA'''
                                                """},
                { "role": "user", "content": report}
            ]
        )
        PROMT = PROMT + response.choices[0].message.content
        return jsonify({"reply": response.choices[0].message.content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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

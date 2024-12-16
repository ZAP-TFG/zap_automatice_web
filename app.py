from flask import Flask, render_template, request, jsonify
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

app = Flask(__name__)
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
    return render_template('vulnerabilities.html', form=form)

def allowed_file(filename):
    """Verifica si el archivo tiene una extensión permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/process_scan', methods=['POST'])
def process_scan():
    url = request.form.get('url')
    intensity = request.form.get('intensity')
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

@app.route('/chatget', methods=['POST'])
def chatget():
    client = openai_client()
    user_message = request.json.get('message')
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente experto en vulnerabilidades web"},
                { "role": "user", "content": user_message}
            ]
        )
        return jsonify({"reply": response.choices[0].message.content})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chatconfig', methods=['POST'])
def chatconfig():
    client = openai_client()
    user_message = request.json.get('message')
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistento al que le van a pasar una configuracion y tu tienes que sacar solo la url, la fecha en formato Datetime y la intesidad, sacamelo en formato JSON"},
                { "role": "user", "content": user_message}
            ]
        )
        return jsonify({"reply": response.choices[0].message.content})
    except Exception as e:
        logging.error("error al comunicarse con la api")
        exit(1)

@app.route('/api/vulnerabilidaes', methods=['POST'])
def chat_sql():
    client = openai_client()
    user_message = request.json.get('message')
    inspector = inspect(db.engine)
    columnas = inspector.get_columns("reportes_vulnerabilidades_url")

    try:
        # Interactuar con OpenAI para obtener la consulta SQL
        response = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente especializado en consultas SQL al que le voy a pasar la informacion de la tabla de la bbdd para que pueda realizar su consulta saviendo que la tabla se llama reportes_vulnerabilidades_url. Las vulnerabilidades se encuentran en el report_file. Solo quiero la consulta, no quiero explicaiones ni que pongas ```sql "},
                {"role": "system", "content": f"{columnas}"},
                {"role": "user", "content": user_message}
            ]
        )
        # Validar la respuesta de OpenAI
        if not response or not response.choices or not response.choices[0].message.content:
            raise ValueError("Respuesta inválida o incompleta de OpenAI")
        
        sql_query = response.choices[0].message.content
        if not sql_query.lower().startswith("select"):
            raise ValueError(f"Consulta SQL inválida: {sql_query}")

        # Ejecutar la consulta SQL
        query = text(sql_query)
        try:
            resultados = db.session.execute(query).fetchall()
        except Exception as e:
            logging.error(f"Error al ejecutar la consulta SQL: {e}")
            return jsonify({"error": "Error en la consulta SQL.", "details": str(e)}), 400

        # Procesar resultados
        try:
            report_file = [json.loads(fila[0]) for fila in resultados]
        except json.JSONDecodeError as e:
            logging.error(f"Error al decodificar JSON: {e}")
            return jsonify({"error": "Error al procesar resultados.", "details": str(e)}), 500

        json_file = json.dumps(report_file, indent=4)
        response2 = chat_resum_vul(client, json_file)

        # Continuar con el resto de la lógica
        url = None
        for fila in report_file:
            if 'site' in fila:
                for site in fila['site']:
                    if '@name' in site:
                        url = site['@name']
            if url:
                break

        vul_urls = Reportes_vulnerabilidades_url.query.filter_by(target_url=url).order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).limit(len(json_file)).all()
        data = {
            "chart_data": {
                "labels": ["Info", "Low", "Medium", "High"],
                "data_first_row": [
                    vul_urls[0].vul_altas if len(vul_urls) > 0 else 0,
                    vul_urls[0].vul_medias if len(vul_urls) > 0 else 0,
                    vul_urls[0].vul_bajas if len(vul_urls) > 0 else 0,
                    vul_urls[0].vul_info if len(vul_urls) > 0 else 0,
                ],
                "data_second_row": [
                    vul_urls[1].vul_altas if len(vul_urls) > 1 else 0,
                    vul_urls[1].vul_medias if len(vul_urls) > 1 else 0,
                    vul_urls[1].vul_bajas if len(vul_urls) > 1 else 0,
                    vul_urls[1].vul_info if len(vul_urls) > 1 else 0,
                ]
            }
        }
        return jsonify({"reply": response2, "chart_data": data})

    except Exception as e:
        logging.error(f"Error al comunicarse con la API: {e}")
        return jsonify({"error": "Ocurrió un error en el servidor.", "details": str(e)}), 500


def chat_resum_vul(client, bbdd_data):
    try:

        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente especializado en vulnerabilidades WEB al que le van a pasar uno o dos reportes y lo mas resumido posible sacar las diferencias y vulnerabilidades de cada uno"},
                {
                    "role": "user",
                    "content": bbdd_data
                }
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        logging.error(f"Error al interactuar con el LLM")

if __name__ == '__main__':
    init_sheduler_scans()
    app.run(debug=True)

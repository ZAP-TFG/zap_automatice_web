from flask import Flask, render_template, request, jsonify
from forms import *
from scanner import *
from werkzeug.utils import secure_filename
import os
from extensions import *
from flask_migrate import Migrate
from datetime import datetime
from openai import OpenAI

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


@app.route('/')
@app.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    form = ScanForm() 
    return render_template('scan.html', form=form)


def allowed_file(filename):
    """Verifica si el archivo tiene una extensión permitida"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/process_scan', methods=['POST'])
def process_scan():
    # Recoger datos del formulario
    url = request.form.get('url')
    intensity = request.form.get('intensity')
    scheduled = request.form.get('scheduled') == 'true'  
    dateTime = request.form.get('dateTime')  
    apiScan = request.form.get('apiScan') == 'true'  
    file = request.files.get('file')  

    if not url or not intensity:
        return jsonify({'status': 'error', 'message': 'Faltan datos obligatorios'}), 400

    if scheduled:
        if not dateTime:
            return jsonify({'status': 'error', 'message': 'La fecha y hora son requeridas para programar el escaneo.'}), 400

        try:
            dateTime = datetime.strptime(dateTime, '%Y-%m-%dT%H:%M')
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Formato de fecha y hora inválido.'}), 400

    file_path = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
    elif file:
        return jsonify({'status': 'error', 'message': 'Tipo de archivo no permitido'}), 400

    # Guardar el escaneo
    escaneo_completado = Escaneres_completados(
        target_url=url,
        intensidad=intensity,
        estado='EN PROCESO',
        api_scan=apiScan,  
        file_path=file_path, 
        #fecha_programada=dateTime 
    )

    db.session.add(escaneo_completado)
    db.session.commit()

    if not scheduled:
        try:
            zap = connection_to_zap()
            is_in_sites(zap, url)
            scan_id = active_scan(zap, url, intensity)
            escaneo_completado.estado = 'COMPLETADO'
            db.session.commit()
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

if __name__ == '__main__':
    app.run(debug=True)

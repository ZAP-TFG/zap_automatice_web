from app import app,db
import datetime
from models import Escaneo_programados
from google import genai
from sqlalchemy import text

def input_user():
    pregunta = input("Introduce pregunta: ")
    return pregunta
def prueba():
    with app.app_context():
        pregunta = input_user()
        prompt_text = f"""
        Eres un asistente especializado en consultas SQL. Te voy a pasar los atributos del modelo de la tabla y vas a tener que responder con el formato string solo la consulta sin COMILLAS. 
        EJEMPLO DE CONSULTA: 
                 SELECT * FROM reportes_vulnerabilidades_url WHERE vul_altas LIKE '%XSS%' OR vul_medias LIKE '%XSS%' OR vul_bajas LIKE '%XSS%' OR vul_info LIKE '%XSS%';
        no puedes incluir  nunca el report_file cuando re preguntan por vulnerabilidades.
        class Escaneo_programados(db.Model):
            __tablename__ = 'reportes_vulnerabilidades_url'  
    
            id 
            target_url 
            vul_altas = db.Column(JSON, nullable=True)
            vul_medias = db.Column(JSON, nullable=True)
            vul_bajas = db.Column(JSON, nullable=True)
            vul_info = db.Column(JSON, nullable=True)
            fecha_scan = db.Column(db.DateTime, default=datetime.now(timezone.utc)) 
            report_file = db.Column(JSON, nullable=True)
        La pregunta proporcionada por el usuario es: {pregunta}
        """
        
        client = genai.Client(api_key="AIzaSyAcSiAiJ-OpQPHRUh0YWnIZ02KAt3pGOOY")
        response = client.models.generate_content(
            model="gemini-2.0-flash", contents=prompt_text
        )

        query = text(response.text)
        print(query)
        result = db.session.execute(query).fetchall()
        # escaneo = Escaneo_programados.query.filter(Escaneo_programados.target_url == "https://example.com/").first()
        print(result)

prueba()
#with app.app_context():
    #query = text("SELECT * FROM escaneos_programados WHERE fecha_programada LIKE '2025-03-13%'")
    #result = db.session.execute(query)
    #rows = result.fetchall()
   # print(rows)
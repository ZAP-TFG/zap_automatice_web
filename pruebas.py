# from zapv2 import ZAPv2
# import time
# import logging
# from dotenv import load_dotenv
# import os

# #def load_env():
# load_dotenv()

# def connection_to_zap():
#     try:
#         zap = ZAPv2(apikey=os.getenv("ZAP_API_KEY"),proxies={'http': 'http://127.0.0.1:8081'})
#         logging.info(zap.core.version)
#         return zap
#     except Exception as error:
#         logging.error(f"Error trying to connect to API: {error}")
#         exit(1)

# url = 'http://example.com'
# nombre = 'gabri'
# zap = connection_to_zap()
# zap.core.new_session(name="sesion_unica", overwrite=True)
# time.sleep(2)
# zap.core.access_url(url)
# time.sleep(1)
# scan_id = zap.ascan.scan(url)
# alerts = zap.alert.alerts_by_risk(url=url)
# alerts_high = alerts.get('Informational')
# print(alerts_high)

from app import app
from models import *
from sqlalchemy.inspection import inspect
from dotenv import load_dotenv
import os
from openai import OpenAI
import logging
from sqlalchemy import text
import json

load_dotenv()

def openai_client():
    openai_key = os.getenv('OPENAI_API_KEY')
    if not openai_key:
        logging.error("Falta openai_key")
        exit(1)
    return OpenAI(api_key=openai_key)

def interact_with_gpt(client,prompt, column):
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente especializado en consultas SQL al que le voy a pasar la informacion de la tabla de la bbdd para que pueda realizar su consulta saviendo que la tabla se llama reportes_vulnerabilidades_url. Las vulnerabilidades se encuentran en el report_file. Solo quiero la consulta, no quiero explicaiones ni que pongas ```sql "},
                {"role": "system", "content": f"{column}"
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        logging.error(f"Error al interactuar con el LLM")


def interact_with_gpt2(client,prompt):
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente especializado en vulnerabilidades WEB al que le van a pasar un reporte y tiene que sacar las vulnerabilidades que tiene, clasificarlas segun severidad y decir como solventarlas"},
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        logging.error(f"Error al interactuar con el LLM")

with app.app_context():
    inspector = inspect(db.engine)
    columnas = inspector.get_columns("reportes_vulnerabilidades_url")
    for column in columnas:
        print(column)

    pregunta = input("Reliza una consulta SQL al chat:  ")
    client = openai_client()
    respuesta = interact_with_gpt(client,pregunta, columnas)
    print(respuesta)

    query = text(respuesta)
    resultados = db.session.execute(query).fetchall()

    print(resultados)
    report_file = [json.loads(fila[0]) for fila in resultados]
    json_file = json.dumps(report_file, indent=4)
    print(json_file)
    url = set()
    for fila in report_file:
        if 'site' in fila:
            for site in fila['site']:
                if '@name' in site:
                    url = site['@name']
                    break
    print(url)
    vul_urls = Reportes_vulnerabilidades_url.query.filter_by(target_url=url).order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).limit(len(json_file)).all()
    for vul in vul_urls:
        print(vul.target_url, vul.fecha_scan, vul.vul_altas, vul.vul_medias, vul.vul_bajas, vul.vul_info)
    # respuesta2 = interact_with_gpt2(client, json_file)
    # print(respuesta2)
    

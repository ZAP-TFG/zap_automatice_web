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
import time
import pdb
load_dotenv()

def openai_client():
    openai_key = os.getenv('OPENAI_API_KEY')
    if not openai_key:
        logging.error("Falta openai_key")
        exit(1)
    return OpenAI(api_key=openai_key)

def interact_with_gpt_context(client,prompt):
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": """  Eres un assitente especializado en sacar el contexto de lo que te estan pidiendo. Lo que saques tiene que ser en formato JSON. Te voy a poner ejemplos:
                                                    user= quiero que me saques los utlimos reportes de https://example.com/ y tu tienes que sacar algo como esto: 'contexto' : 'reportes', 'message': 'quieero que me saques los utlimos reportes de https://example.com/'.
                                                    1. Cuanto de pidan configurar o programar un escaner el contexto sera: configuracion
                                                    2. posibles contextos: reportes, vulnerabilidades y configuracion"""},
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        logging.error(f"Error al interactuar con el LLM")

def interact_with_gpt_sql_reports(client,prompt, column):
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente especializado en consultas SQL al que le voy a pasar la informacion de la tabla de la bbdd para que pueda realizar su consulta saviendo que la tabla se llama reportes_vulnerabilidades_url. Solo quiero la consulta, no quiero explicaiones ni que pongas ```sql . Cuando te pidan reportes tienes que sacar report_file y cuando te pidan vulnerabilidades tambien"},
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

def interact_with_gpt_sql_vulnerabilidades(client,prompt, column):
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente especializado en consultas SQL al que le voy a pasar la informacion de la tabla de la bbdd para que pueda realizar su consulta saviendo que la tabla se llama reportes_vulnerabilidades_url. Solo quiero la consulta, no quiero explicaiones ni que pongas ```sql . Cuando te pidan las vulnerabilidades tendras que sacar los lo que corresponda a vulnerabilidades:  vul_altas, vul_medias,vul_bajas ,vul_info"},
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

def interact_with_gpt_compare_reports(client,prompt):
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente especializado en vulnerabilidades WEB al que le van a pasar uno o dos reportes y en caso de que haya dos tener que compararlos. En caso de que sea uno hacer un resumen corto de vulnerabilidadddes que tiene y posibles soluciones"},
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        return completion.choices[0].message.content
    except Exception as e:
        logging.error(f"Error al interactuar con el LLM")

def interact_with_gpt_config(client,prompt):
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistento al que le van a pasar una configuracion y tu tienes que sacar solo la url, la fecha en formato Datetime y la intesidad, sacamelo en formato JSON sin ```json. solo el JSON"},
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
    try: 
        inspector = inspect(db.engine)
        columnas = inspector.get_columns("reportes_vulnerabilidades_url")
        for column in columnas:
            print(column)
    except Exception as e:
        logging.error(f"Error 1 al tratar de sacar esquema de la BBDD {e}")

    pregunta = input("Reliza una consulta al chat:  ")
    client = openai_client()

    try:
        respuesta = json.loads(interact_with_gpt_context(client,pregunta))
        contexto = respuesta['contexto']
        message= respuesta['message']
        print(contexto)
    except Exception as e: 
        logging.error(f"Error 2 al conectarse al chat o al parsear respuesta en JSON: {e}")

    if contexto == "configuracion":
        try:
            time.sleep(0.5)
            respuesta_config = interact_with_gpt_config(client,message)
            print(respuesta_config)
        except Exception as e:
            logging.error(f"Error 3: {e}")
    elif contexto == "reportes":
        try:
            time.sleep(0.5)
            query = interact_with_gpt_sql_reports(client,message, columnas)
            query = text(query)
            print(query)

            pdb.set_trace()

            consulta_bbdd = db.session.execute(query).fetchall()
            print(consulta_bbdd)

            pdb.set_trace()
            report_file = [json.loads(fila[0]) for fila in consulta_bbdd]
            json_file = json.dumps(report_file, indent=4)
            print(json_file)

            pdb.set_trace()
            time.sleep(0.5)
            respuesta_compare_reports = interact_with_gpt_compare_reports(client,json_file)
            print(respuesta_compare_reports)
        except Exception as e:
            logging.error(f"Error 4:{e}")
    elif contexto == "vulnerabilidades":
        try: 
            pdb.set_trace()
            time.sleep(0.5)
            query_vul = text(interact_with_gpt_sql_vulnerabilidades(client, message, columnas))
            print(query_vul)
        except Exception as e:
            logging.error(f"Error 5:{e}")

    # respuesta = interact_with_gpt(client,pregunta, columnas)
    # print(respuesta)

    # query = text(respuesta)
    # resultados = db.session.execute(query).fetchall()
    # print(resultados)

    # report_file = [json.loads(fila[0]) for fila in resultados]
    # json_file = json.dumps(report_file, indent=4)
    # print(json_file)
    # url = set()
    # for fila in report_file:
    #     if 'site' in fila:
    #         for site in fila['site']:
    #             if '@name' in site:
    #                 url = site['@name']
    #                 break
#     print(url)
#     vul_urls = Reportes_vulnerabilidades_url.query.filter_by(target_url=url).order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).limit(len(json_file)).all()
#     for vul in vul_urls:
#         print(vul.target_url, vul.fecha_scan, vul.vul_altas, vul.vul_medias, vul.vul_bajas, vul.vul_info)
# pregunta = input("Escribe pregunta: ")
# respuesta2 = interact_with_gpt_context(client, pregunta)
# print(respuesta2)
    

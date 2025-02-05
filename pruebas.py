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
import re
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
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content":  """  
                 #OBJETIVOS
                 Eres un asistente especializado en sacar el contexto de lo que te están pidiendo y experto en ciberseguridad. La salida será un JSON.
                 Tendrás que sacar un porcentaje de pertenencia a cada categoría
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
            ],
            temperature=0.1
        )
        return(completion.choices[0].message.content)
    except Exception as e:
        logging.error(f"Error al interactuar con el LLM")

def preguntas(client, prompt):
    try:
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": """  
                #####OBJETIVOS
                 Eres un asistente especializado en el area de ciberseguridad. Te haran preguntas y tendras que responder la manera mas clara 
                 y precisa posible. La salida sera en formato markdown.
                """},
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.8
        )
        print(completion.choices[0].message.content)
    except Exception as e:
        logging.error(f"Error en la consulta preguntas al GPT: {e}")

def comparacion (client, prompt, message):
    try:
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": """  
                Rol: Eres un experto en ciberseguridad. Se te proporcionarán entre 2 y 4 reportes de vulnerabilidades. Cada reporte incluye la siguiente información:
                Listado de vulnerabilidades detectadas (por ejemplo, nombre, descripción o CWE).
                Fecha de generación o versión.
                Objetivo:
                Comparar los reportes, identificando las diferencias clave en cuanto a vulnerabilidades.
                Listar exclusivamente las vulnerabilidades de cada reporte (sin repeticiones innecesarias).
                Resaltar cualquier mejora o reducción de vulnerabilidades encontradas entre cada reporte.
                Todo debe presentarse en formato Markdown.
                Destaca las vulnerabilidades que se repiten en más de un reporte (si aplica).
                Observa si alguna vulnerabilidad se resolvió o ya no aparece en un reporte posterior.
                Enfatizar las mejoras
                Si la vulnerabilidad “X” estaba presente en el Reporte 1 pero ya no aparece en el Reporte 2 (o 3, 4…), indícalo para mostrar una posible mejora.
                Menciona explícitamente dónde se nota corregida o ausente.
                Formato de salida
                Usa Markdown para estructurar tu respuesta.
                Separa el contenido en secciones descriptivas (por ejemplo, “Vulnerabilidades encontradas por reporte”, “Diferencias clave”, “Mejoras detectadas”).
                Emplea viñetas, listas numeradas o tablas en caso de que sea útil para clarificar la información.
                Ejemplo de respuesta esperada (en Markdown)
                text
                # Comparativa de Reportes de Vulnerabilidades

                ## Reporte 1 (Fecha: 2023-10-01)
                - **SQL Injection** (CWE-89)
                - **Broken Access Control** (CWE-200)

                ## Reporte 2 (Fecha: 2023-10-15)
                - **Broken Access Control** (CWE-200)
                - **Cross-Site Scripting (XSS)** (CWE-79)

                ## Diferencias clave
                - **Novedad en Reporte 2**: Cross-Site Scripting (XSS) no existía en Reporte 1.  
                - **Ausencia**: SQL Injection ya no aparece en Reporte 2, lo que indica una posible corrección.

                ## Mejoras detectadas
                - Al eliminar la vulnerabilidad “SQL Injection”, se demuestra que se corrigió o mitigó en la transición del Reporte 1 al Reporte 2.
                """},
                {
                    "role": "user",
                    "content": prompt
                },
                {
                    "role": "user",
                    "content": message
                }
            ],
            temperature=0.8
        )
        print(completion.choices[0].message.content)
    except Exception as e:
        logging.error(f"Error en comparacion del GPT: {e}")

def vulnerabilidades_2(client, prompt1, message):
    try:
        completion = client.chat.completions.create(
            model="gpt-3.5-turbo",
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
                Si el usuario pide un resumen (por ejemplo): “Hazme un resumen de las vulnerabilidades encontradas.”
                Acción: El resumen debe incluir un listado de vulnerabilidades sin repeticiones, la URL asociada a cada vulnerabilidad, el CWE y la categoría de OWASP Top 10 a la que pertenece. Todo el contenido debe presentarse en formato Markdown.
                Formato Markdown
                Siguiendo las pautas recomendadas para la creación de reportes de seguridad, cada respuesta deberá entregarse en un formato Markdown sencillo, por ejemplo:
                Listas con guiones o numeradas.
                Uso de negritas o itálicas cuando corresponda.
                Agrupación de vulnerabilidades según sea necesario.
                (Para más información sobre la creación de reportes en formato Markdown, puedes consultar 14.)
                Ejemplos
                Caso 1: Solo listar vulnerabilidades
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
                Caso 3: Resumen de un reporte
                Usuario:
                “Hazme un resumen de las vulnerabilidades encontradas.”
                Tu respuesta (listado sin repeticiones + URL + descripcion + CWE + OWASP Top 10 en Markdown):
                    **Resumen de vulnerabilidades detectadas**

                    - **Vulnerabilidad**: Broken Access Control  
                    **URL**: http://example.com  
                    **DESCRIPCION**: 
                    **CWE**: CWE-200  
                    **OWASP Top 10**: A01:2021 (Broken Access Control)

                    - **Vulnerabilidad**: SQL Injection  
                    **URL**: http://example.com  
                    **DESCRIPCION**:
                    **CWE**: CWE-89  
                    **OWASP Top 10**: A03:2021 (Inyección)

                    - **Vulnerabilidad**: Cross-Site Scripting (XSS)
                    **URL**: http://example.com 
                    **DESCRIPCION**: 
                    **CWE**: CWE-79  
                    **OWASP Top 10**: A07:2021 ()
                
                """},
                {
                    "role": "user",
                    "content": prompt1
                },
                {
                    "role": "user",
                    "content": message
                }
            ],
            temperature=0.8
        )
        print(completion.choices[0].message.content)
    except Exception as e:
        logging.error(f"Error en vulnerbilidades_2 del GPT: {e}")

def consultas_generales(client, message):
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

                    Tabla: escaneos_progrmados
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
                    -  hazme un resumen del ultimo reporte de http://example.com
                        Esta petición requiere consultar la tabla reportes_vulnerabilidades_url y extraer únicamente los dos reportes más recientes relacionados con target_url = 'http://example.com', devolviendo, por ejemplo, los campos del reporte (en concreto report_file si fuera necesario).
                        Ejemplo de respuesta (solo SQL):
                            SELECT report_file
                            FROM reportes_vulnerabilidades_url
                            WHERE target_url = 'http://example.com'
                            ORDER BY fecha_scan DESC
                            LIMIT 1;
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


if __name__ == '__main__':
    client = openai_client()
    with app.app_context():
        while True:
            prompt = input("Escribe consulta: ")
            result = interact_with_gpt_context(client,prompt)
            result = json.loads(result)
            contexto = result['contexto']
            message = result['message']
            print(contexto, "\n", message)
            if float(contexto['preguntas']) > 0.7:
                preguntas(client,message)
            elif float(contexto['comparacion']) > 0.7:
                escenario = 'comparacion'
                print(message)
                time.sleep(0.5)
                response = consultas_generales(client, message)
                query = text(response)
                print(query)
                pdb.set_trace()
                result = db.session.execute(query).fetchall()
                print(result)
                consulta_bbdd = [dict(row._mapping) for row in result]
                json_data = json.dumps(consulta_bbdd, indent=4)
                print(json_data)
                pdb.set_trace()
                comparacion(client,json_data,message)
                
            elif float(contexto['vulnerabilidades']) > 0.7:
                escenario = 'vulnerabilidades'
                consultas_generales(client, message, escenario)
            elif float(contexto['reportes']) > 0.7:
                escenario = 'reportes'
                time.sleep(0.5)
                response = consultas_generales(client, message)
                query = text(response)
                print("Query generado:", query)
                pdb.set_trace()
                result = db.session.execute(query).fetchall()
                print("Resultados crudos de la BD:", result)
                consulta_bbdd = [dict(row._mapping) for row in result]
                json_data = json.dumps(consulta_bbdd, indent=4)
                print("Resultados en formato JSON:")
                print(json_data)
                pdb.set_trace()
                vulnerabilidades_2(client, json_data, message)

            elif float(contexto['historial']) > 0.7:
                escenario = 'historial'
                consultas_generales(client, message, escenario)

# def interact_with_gpt_sql_reports(client,prompt, column):
#     try:
#         completion = client.chat.completions.create(
#             model="gpt-4-turbo",
#             messages=[
#                 {"role": "system", "content": "Eres un asistente especializado en consultas SQL al que le voy a pasar la informacion de la tabla de la bbdd para que pueda realizar su consulta saviendo que la tabla se llama reportes_vulnerabilidades_url. Solo quiero la consulta, no quiero explicaiones ni que pongas ```sql . Cuando te pidan reportes tienes que sacar report_file y cuando te pidan vulnerabilidades tambien"},
#                 {"role": "system", "content": f"{column}"
#                 },
#                 {
#                     "role": "user",
#                     "content": prompt
#                 }
#             ]
#         )
#         return completion.choices[0].message.content
#     except Exception as e:
#         logging.error(f"Error al interactuar con el LLM")

# def interact_with_gpt_sql_vulnerabilidades(client,prompt, column):
#     try:
#         completion = client.chat.completions.create(
#             model="gpt-4-turbo",
#             messages=[
#                 {"role": "system", "content": "Eres un asistente especializado en consultas SQL al que le voy a pasar la informacion de la tabla de la bbdd para que pueda realizar su consulta saviendo que la tabla se llama reportes_vulnerabilidades_url. Solo quiero la consulta, no quiero explicaiones ni que pongas ```sql . Cuando te pidan las vulnerabilidades tendras que sacar los lo que corresponda a vulnerabilidades:  vul_altas, vul_medias,vul_bajas ,vul_info"},
#                 {"role": "system", "content": f"{column}"
#                 },
#                 {
#                     "role": "user",
#                     "content": prompt
#                 }
#             ]
#         )
#         return completion.choices[0].message.content
#     except Exception as e:
#         logging.error(f"Error al interactuar con el LLM")

# def interact_with_gpt_compare_reports(client,prompt):
#     try:
#         completion = client.chat.completions.create(
#             model="gpt-4-turbo",
#             messages=[
#                 {"role": "system", "content": "Eres un asistente especializado en vulnerabilidades WEB al que le van a pasar uno o dos reportes y en caso de que haya dos tener que compararlos. En caso de que sea uno hacer un resumen corto de vulnerabilidadddes que tiene y posibles soluciones"},
#                 {
#                     "role": "user",
#                     "content": prompt
#                 }
#             ]
#         )
#         return completion.choices[0].message.content
#     except Exception as e:
#         logging.error(f"Error al interactuar con el LLM")

# def interact_with_gpt_config(client,prompt):
#     try:
#         completion = client.chat.completions.create(
#             model="gpt-4-turbo",
#             messages=[
#                 {"role": "system", "content": "Eres un asistento al que le van a pasar una configuracion y tu tienes que sacar solo la url, la fecha en formato Datetime y la intesidad, sacamelo en formato JSON sin ```json. solo el JSON"},
#                 {
#                     "role": "user",
#                     "content": prompt
#                 }
#             ]
#         )
#         return completion.choices[0].message.content
#     except Exception as e:
#         logging.error(f"Error al interactuar con el LLM")

# with app.app_context():
#     try: 
#         inspector = inspect(db.engine)
#         columnas = inspector.get_columns("reportes_vulnerabilidades_url")
#         for column in columnas:
#             print(column)
#     except Exception as e:
#         logging.error(f"Error 1 al tratar de sacar esquema de la BBDD {e}")

#     pregunta = input("Reliza una consulta al chat:  ")
#     client = openai_client()

#     try:
#         respuesta = json.loads(interact_with_gpt_context(client,pregunta))
#         contexto = respuesta['contexto']
#         message= respuesta['message']
#         print(contexto)
#     except Exception as e: 
#         logging.error(f"Error 2 al conectarse al chat o al parsear respuesta en JSON: {e}")

#     if contexto == "configuracion":
#         try:
#             pdb.set_trace()
#             time.sleep(0.5)
#             respuesta_config = interact_with_gpt_config(client,message)
#             print(respuesta_config)
#         except Exception as e:
#             logging.error(f"Error 3: {e}")
#     elif contexto == "reportes":
#         try:
#             time.sleep(0.5)
#             query = interact_with_gpt_sql_reports(client,message, columnas)
#             query = text(query)
#             print(query)

#             pdb.set_trace()

#             match = re.search(r"targer_url = '([^']+)'",query)
#             if match:
#                 url = match.group(1)
#                 print("URL: ",url)

#             pdb.set_trace()

#             consulta_bbdd = db.session.execute(query).fetchall()
#             print(consulta_bbdd)

#             pdb.set_trace()

#             report_file = [json.loads(fila[0]) for fila in consulta_bbdd]
#             json_file = json.dumps(report_file, indent=4)
#             print(json_file)

#             pdb.set_trace()

#             time.sleep(0.5)
#             respuesta_compare_reports = interact_with_gpt_compare_reports(client,json_file)
#             print(respuesta_compare_reports)
#         except Exception as e:
#             logging.error(f"Error 4:{e}")
#     elif contexto == "vulnerabilidades":
#         try: 
#             pdb.set_trace()


#             time.sleep(0.5)
#             query_vul = text(interact_with_gpt_sql_vulnerabilidades(client, message, columnas))
#             print(query_vul)
#         except Exception as e:
#             logging.error(f"Error 5:{e}")


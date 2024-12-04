
# from openai import OpenAI
# client = OpenAI()

# def interact_with_gpt(prompt):
#     completion = client.chat.completions.create(
#         model="gpt-3.5-turbo",
#         messages=[
#             {"role": "system", "content": "Eres un asistente que ayuda con todo lo que le digan."},
#             {
#                 "role": "user",
#                 "content": prompt
#             }
#         ]
#     )
#     return completion

# if __name__== '__main__':
#     pregunta = input("escribe pregunta: ")
#     respuesta = interact_with_gpt(pregunta)
#     print(respuesta.choices[0].message)

from zapv2 import ZAPv2
import time
import logging
from dotenv import load_dotenv
import os
from openai import OpenAI


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("zap_logs.log", mode="w", encoding="utf-8")
    ]
)
def load_env():
    load_dotenv()

def connection_to_zap():
    try:
        zap = ZAPv2(apikey=os.getenv("ZAP_API_KEY"),proxies={'http': 'http://127.0.0.1:8081'})
        logging.info(zap.core.version)
        return zap
    except Exception as error:
        logging.error(f"Error trying to connect to API: {error}")
        exit(1)

def is_in_sites(zap,url):
    try:
        sites = zap.core.sites
        if url not in sites:
           zap.core.access_url(url)
           time.sleep(1)
        else:
            pass
            logging.info("Url in Sites")
    except Exception as error:
        logging.error(f"Error trying to add URL in Sites: {error}")
        exit(1)

def scan_strength(zap,strength):
    count = 0
    try:
        for policy_id in range(5):
            zap.ascan.set_policy_attack_strength(policy_id, strength.upper())
            zap.ascan.set_policy_alert_threshold(policy_id, 'DEFAULT')

        scan_info_strength = zap.ascan.policies()
        time.sleep(2)
        for policy in scan_info_strength:
            if policy['attackStrength'] == strength.upper():
                count+=1
        if count == 5:
            logging.info("Attack_Strength Configured")
        else:
            logging.error("Attack Strength NOT Configured")
            raise
    except Exception as error:
        logging.error(f"Error trying to set scan strength: {error}")
        exit(1)

def active_scan(zap,url,strength):
    scan_strength(zap,strength)
    time.sleep(1)
    try:
        scan_id = zap.ascan.scan(url)
        while True:
            if int(zap.ascan.status(scan_id)) < 100:
                logging.info(f"Scan Progress: {zap.ascan.status(scan_id)}")
                time.sleep(2)
            elif int(zap.ascan.status(scan_id)) == 100:
                logging.info("Scan Complete -> 100%")
                break
    except Exception as error:
        logging.error(f"Error trying to Scan {url}: {error}")
        exit(1)


def openai_client():
    openai_key = os.getenv('OPENAI_API_KEY')
    if not openai_key:
        logging.error("Falta openai_key")
        exit(1)
    return OpenAI(api_key=openai_key)

def interact_with_chatgpt(client,prompt):
    """intentar enviar un comando al chatgpt que lo interprete y podamos sacar las indicaciones para que puede interactuar con el codigo"""
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente traduce lo que te dicen y saca solo la url y la intensidad con la que se va a hacer el escaneo nada mas y quiero que lo saques en una sola linea "},
                { "role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        logging.error(f"Error al intentar interactuar con el Chat {e}")
        exit(1)
def parsear_message(respuesta):
    try:
        parts = response.split()
        if len(parts) != 2:
            logging.error("La respuesta no contiene el formato esperado: ")
            exit(1)
        url, intensidad = parts
        return url, intensidad
    except Exception as e:
        logging.error(f"Error al parsear la respuesta del LLM: {e}")
        exit(1)
        
# if __name__ == "__main__":
#     url='http://pruebachatweb.cofares.es'
#     strength='low'
#     load_env()
#     zap = connection_to_zap()
#     is_in_sites(zap,url)
#     scan_strength(zap,strength)
#     active_scan(zap,url,strength)

if __name__ == "__main__":
    load_env()
    client_openai = openai_client()
    comando = input("Escribe una instruccion: (ejemplo: 'Escanea http://example.com con intensidad low): ")
    response = interact_with_chatgpt(client_openai, comando)

    url, intensidad = parsear_message(response)
    print(f"\n - URL: {url}\n - Intesidad: {intensidad}")
    zap = connection_to_zap()
    is_in_sites(zap,url)
    active_scan(zap, url, intensidad)



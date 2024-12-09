from dotenv import load_dotenv
import os
from openai import OpenAI
import logging
def load_env():
    load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("zap_logs.log", mode="w", encoding="utf-8")
    ]
)

def openai_client():
    openai_key = os.getenv('OPENAI_API_KEY')
    if not openai_key:
        logging.error("Falta openai_key")
        exit(1)
    return OpenAI(api_key=openai_key)

def read_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        logging.error(f"Error al leer el archivo: {e}")
        exit(1)

def interact_with_chatgpt(client,prompt,prompt2):
    try:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "Eres un asistente experto en el area de ciberseguridad al que le van a pasar 2 informes, el archivo que tiene en el nombre el numero 2 es el mas reciente. Necesito que me hagas una comparativa entre el viejo y el nuevo y que alertas se han solventado y saca que porcentaje de alertas han sido solventadas."},
                { "role": "user", "content": prompt},
                { "role": "user", "content": prompt2}
            ]
        )
        return response
    except Exception as e:
        logging.error(f"Error al intentar interactuar con el Chat {e}")
        exit(1)


if __name__== '__main__':
    client = openai_client()
    path_file = "/home/kalilinux22/2024-12-04-ZAP-Report-.json"
    path_file2= "/home/kalilinux22/2024-12-04-ZAP-Report-2.json"
    archivo1 = read_file(path_file)
    archivo2 = read_file(path_file2)
    respuesta = interact_with_chatgpt(client,archivo1,archivo2)
    print(respuesta.choices[0].message.content)


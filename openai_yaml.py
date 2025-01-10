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


def interact_with_gpt(client,prompt):
    try:
        completion = client.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "Eres un asistente especializado en generar archivos YAML para configurar escaneos automatizados en OWASP ZAP. No quiero que el archivo tenga comentarios tuyos. SOLO EL CODIGO. Te paso un codigo para que lo tomes como ejemplo."},
                {"role": "system", "content": """
                    Ejemplo de YAML:
                   env:
                        - name: Default Environment
                            urls:
                            - http://example.com
                    jobs:
                        - name: Spider
                            type: spider
                            parameters:
                            context: Default Context
                            maxDepth: 5 
                        - name: Active Scan
                            type: activeScan
                            parameters:
                            context: Default Context
                            attackStrength: Medium
                        - name: Generar Reporte PDF
                            type: report
                            parameters:
                            format: PDF
                            filePath: /path/to/report.pdf
                    schedule:
                        - time: '2023-12-05T12:00:00'
                        """
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )
        return completion
    except Exception as e:
        logging.error(f"Error al interactuar con el LLM")

def save_yaml(content,file_name="/home/kalilinux22/Documents/ZAP_TFG/Automated_task3.yaml"):
    try:
        with open(file_name, 'w') as file:
            file.write(content)
        logging.info("Archivo YAML guardado")
    except Exception as e:
        logging.error(f"Informe no generado ni guardado: {e}")

if __name__== '__main__':
    client = openai_client()
    pregunta = input("escribe pregunta: ")
    respuesta = interact_with_gpt(client,pregunta)
    save_yaml(respuesta.choices[0].message.content)




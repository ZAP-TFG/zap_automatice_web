from google import genai
from dotenv import load_dotenv
import os, datetime, json

def ejecutar_escaner(user_input):

    prompt_text = f"""
            Eres un asistente que tiene que sacar la información más relevante de un texto. En este caso tendras que sacar:
            - URL
            - fecha y hora del escaneo en formato: %Y-%m-%dT%H:%M
            - intensidad del escaneo: DEFAULT, LOW, MEDIUM, HIGH, INSANE
            - si el escaneo es programado o no: True o False
            IMPORTANTE:NO PONGAS COMILLAS `````, PUNTOS Y COMAS, ni nada que no sea JSON.
            La pregunta proporcionada por el usuario es: {user_input}
            El formato de salida es el siguiente y entre corchetes:
                'url': 'https://example.com',
                'fecha_hora: '2023-10-01T12:00',
                'intensidad": 'DEFAULT',
                'email': 'example@example.com',
                'programado': true
            Si no puedes encontrar la información, devuelve un JSON vacío.
            """

    client = genai.Client(api_key="AIzaSyAcSiAiJ-OpQPHRUh0YWnIZ02KAt3pGOOY")
    response = client.models.generate_content(
        model="gemini-2.0-flash", contents=prompt_text,
        config={
        'response_mime_type': 'application/json',
    },
    )   
    result = json.loads(response.text.strip())
    print(result)
try:
    while True:
        user_input = input("Introduce la pregunta: ")
        ejecutar_escaner(user_input)
except KeyboardInterrupt:
    print("\nSaliendo...")

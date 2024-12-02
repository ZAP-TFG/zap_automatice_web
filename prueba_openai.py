
from openai import OpenAI
client = OpenAI()

def interact_with_gpt(prompt):
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "Eres un asistente que ayuda con todo lo que le digan."},
            {
                "role": "user",
                "content": prompt
            }
        ]
    )
    return completion

if __name__== '__main__':
    pregunta = input("escribe pregunta: ")
    respuesta = interact_with_gpt(pregunta)
    print(respuesta.choices[0].message)
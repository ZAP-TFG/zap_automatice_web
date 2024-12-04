# Comentarios varios de lo que voy probando

***04/11/2024***
**ASi es como es la respuesta del chat**
    {
        "id": "cmpl-abc123",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "gpt-3.5-turbo",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "La capital de Francia es París."
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 9,
            "total_tokens": 19
        }
    }
Por lo que si queremos acceder al mensaje tendremos que llamar a respuesta.choices[0].message.content
Teniendo en cuenta que puede haber mas de una respuesta nos quedamos con la primera

- Intentar ver si hay alguna "libreria" que nos permita parsaer mejor la informacion que saca el LLM



    
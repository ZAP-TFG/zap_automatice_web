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


#### Probando a que me reporte .yaml
1. Primer intento:
    Quiero que me programes un escaner para http://example.com el dia 5 de diciemrbe a las 12 de la mañana y con intesidad de escaner media.
    archivo: 
        zap_scan_config:
            - scan_name: "Scheduled Scan for example.com"
            - target_url: "http://example.com"
            - schedule:
                start_time: "2023-12-05T12:00:00"
                timezone: "UTC"
            - scan_intensity: "Medium"
2. Segundo intento: 
    cambiamos la descripcion del rol y queremos que solo nos saque el codigo que no de explicaciones.
    "quiero que mr programes un scaner para http://example.com para el 5 de diciembre de 2024 a las 12 de la mañana con intensidad media. Quiero que me ejcute spider pero no quiero que me ejecute el ajax_spider."    
    - name: Scheduled scan on http://example.com
        scanner:
            url: "http://example.com"
            date: "2024-12-05"
            time: "12:00"
            intensity: "Medium"
            spider:
            enabled: true
            ajax_spider:
            enabled: false
3. Tercer Intento: 
    - Descripcion del rol: Eres un asistente especializado en generar archivos YAML para configurar escaneos automatizados en OWASP ZAP. Los archivos deben ser compatibles con sistemas de automatización que utilizan la API de ZAP y seguir las mejores prácticas de organización para facilitar su uso. Tu salida debe ser clara, bien estructurada y válida como YAML. Además, incluye opciones de configuración relevantes como el nombre del escaneo, la URL objetivo, programación con fecha y hora, intensidad, activación del spider, y opciones de autenticación (si no hay autenticación, indícalo como desactivado). Incluye secciones opcionales para el formato del informe y la ubicación del archivo generado.
    - Genera un archivo YAML para un escaneo en http://example.com, programado para el 5 de diciembre de 2024 a las 12:00, con intensidad media, spider habilitado, y sin autenticación.
        zap_scan_config:
            scan_name: "Scan on example.com"
            target_url: "http://example.com"
            schedule:
                date: "2024-12-05"
                time: "12:00"
            intensity: "Medium"
            spider:
                enabled: true
            authentication:
                enabled: false

            report:
            format: "PDF"
            output_file: "scan_report_example_com.pdf"
4. Pruebo a pasarle un ejemplo de reporte.

// Mostrar/ocultar los campos de la fecha y hora según si se selecciona "Schedule"
        // $('#scheduleSwitch').change(function () {
        //     if ($(this).is(':checked')) {
        //         $('#scheduleFields').removeClass('d-none');
        //     } else {
        //         $('#scheduleFields').addClass('d-none');
        //     }
        // });

        ![alt text](image.png)
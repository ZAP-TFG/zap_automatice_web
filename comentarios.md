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

________________________________________________________________________________________________________
#PROMPT ENGINEERING
###PREGUNTAS
1. Como solventarias la vulnerabilidad XSS reflected
2. Para evitar SQLi como sanitizo las entradas
3. Quien es steve jobs
4. Que CWE tiene la vulnerabilidad Path Traversal
5. Me falta CSP que numero de OWASP TOP 10 corresponde
###CONFIGURACION
1. Programame un escaner para http://example.com con intesidad media para el 
de enero a las 12pm
2. Lanzame un escaner a http://example.com para ahora mismo
3. Ejecuta un escaner para ahora mismo de http://gabriel.es
4. Quiero escanear http://romero.gonzalez.es con intesidad media para mañana 
5. Programa un escaneo semanal para http://example.com cada lunes a las 9am.
###HISTORIAL
1. Que hay de nuevo respecto ayer?
2. Cuantos escaneres hay pendientes para hoy?
3. Se ha ejecuta algun escaner hace poco?
4. Proximos escaneres en realizarse?
5. Programacion de escaneres para hoy?
###REPORTES
1. Que vulnerabilidades tiene http://example.com
2. Sacame las vulnerabildiades del ultimo reporte de http://example.com
3. Ultimas alertas obtenidas en el ultimo escaner de http://example.com
4. Cuantas vunerabilidades criticas tiene http://example.com
5. Hazme un resumen del ultimo reporte de http://example.com
###COMPARACION
1. Que diferencia hay entre los dos ultimos reportes de http://example.com
2. Comparame los ultimos 3 reportes de http://example.com
3. Sacame la comparativa de los ultimos reportes de http://example.com
4. Compara los dos ultimos reportes de http://example.com
###VULNERABILIDADES
1. Cuantas vulnerabilidades XSS tenemos en las urls
2. Que urls tienen la alerta SQLi
3. Sacame cuantas urls les falta la cabecera CSP
4. En que urls tenemos mas alertas
5. Tenemos path traversal en alguna de las urls
###GENERAR_REPORTE
1. Generame un reporte de http://example.com en formato JSON
2. Sacame un reporte de http://example.com en pdf
3. Enviame el ultimo reporte de http://example.com 
###CONSULTA_SQL
1. Cambia la periocidad de http://example.com para cada 2 meses
2. Puedes añadir estas urls: ..... con su periocidad a la tabla 
3. Necesito que programes escaneres cada 30 dias para estas urls ... y lo metas en la tabla periocidad
4. Modifica la peiocidad de http://example.com y ponla cada año
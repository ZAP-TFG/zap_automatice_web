### ZapAI Auditor

ZapAI Auditor es una plataforma web que integra OWASP ZAP con modelos de lenguaje avanzados para realizar auditorías de seguridad web de forma automatizada y accesible. La aplicación permite ejecutar y programar escaneos de vulnerabilidades, consultar resultados a través de un chatbot conversacional y generar reportes detallados en formato DOCX con recomendaciones personalizadas. Además, cuenta con funcionalidades para la notificación automática por correo electrónico (a través de SendGrid) y el procesamiento de resultados externos en formato JSON. El sistema está completamente containerizado con Docker, lo que permite un despliegue rápido cualquier entorno compatible.

Para su despliegue y funcionamiento se debe seguir estos pasos:

1. Crear el .env con los siguiente valores:
```bash
ZAP_API_KEY=
ZAP_URL=http://zap:8090

GEMINI_API_KEY=
OPENAI_API_KEY=
SENDGRID_API_KEY=

REPORT_DIR=/app/reportes

APP_USERNAME=
APP_PASSWORD=
FLASK_SECRET_KEY=

PSQL_HOST=db
PSQL_PORT=5432
PSQL_USER=
PSQL_PASSWORD=
DB_NAME=zap_data_base
```

2. Posteriormente desplegar el Docker:
```bash
docker-compose up -d --build

docker exec -it zap_web bash
    flask db init
    flask db migrate -m "first migration"
    flaks db upgrade
```


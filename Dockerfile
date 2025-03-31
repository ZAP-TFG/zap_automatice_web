# Usa una imagen base de Python
FROM python:3.8-slim

# Setea el directorio de trabajo
WORKDIR /app

# Copia los requisitos y luego instala las dependencias
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copia el código de tu aplicación
COPY . /app

# Expone el puerto que va a usar Flask
EXPOSE 5000

# Comando para iniciar Flask con gunicorn
ENTRYPOINT ["/zap_automatic_web/entrypoint.sh"]

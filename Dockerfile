
FROM python:3.13-slim


WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


RUN pip install gunicorn

# Copiar el resto de los archivos
COPY . .

RUN mkdir -p reportes


EXPOSE 5000


CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]

import json
from flask import Flask
from models import db, Reportes_vulnerabilidades_url, Escaneo_programados  # Importa tu modelo y base de datos
from app import app

with app.app_context():

    escaneo = Escaneo_programados.query.filter(Escaneo_programados.target_url == "https://example.com/").first()
    print(escaneo.target_url)


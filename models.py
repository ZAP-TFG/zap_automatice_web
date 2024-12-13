from extensions import *
from datetime import datetime, timezone


class Escaneres_completados(db.Model):
    __tablename__ = 'escaneos_completados'  

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False)
    estado = db.Column(db.String(50), nullable=False)
    fecha_inicio = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    fecha_fin = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    intensidad = db.Column(db.String(50), nullable=False, default='DEFAULT')
    api_scan = db.Column(db.Boolean, default = False)
    api_file = db.Column(JSON,nullable=True)
    report_file = db.Column(JSON, nullable=True) # recoger alertas que umbral medio/alto
    # Relación con la tabla Vulnerabilidades
    vulnerabilidades = db.relationship('Vulnerabilidades', backref='escaneo', lazy=True)

class Vulnerabilidades(db.Model):
    __tablename__ = 'vulnerabilidades'  

    id = db.Column(db.Integer, primary_key=True)
    escaneo_id = db.Column(db.Integer, db.ForeignKey('escaneos_completados.id'), nullable=False)
    severidad = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    url_afectada = db.Column(db.String(200), nullable=False)

class Escaneo_programados(db.Model):
    __tablename__= 'escaneos_progrmados'

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False)
    intensidad = db.Column(db.String(50), nullable=False, default='DEFAULT')
    fecha_programada = db.Column(db.DateTime, nullable=False)
    estado = db.Column(db.String(50), nullable=False, default='PENDIENTE') 
    archivo_subido = db.Column(db.String(200), nullable=True)
    api_scan = db.Column(db.Boolean, default = False)
    api_file = db.Column(JSON,nullable=True)
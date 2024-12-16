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


class Vulnerabilidades_totales(db.Model):
    __tablename__ = 'vulnerabilidades_totales'  

    id = db.Column(db.Integer, primary_key=True)
    escaneos_totales = db.Column(db.Integer, default=0, nullable=False)
    vul_tot_altas = db.Column(db.Integer, default=0, nullable=False)
    vul_tot_medias = db.Column(db.Integer, default=0, nullable=False)
    vul_tot_bajas = db.Column(db.Integer, default=0, nullable=False)
    vul_tot_info = db.Column(db.Integer, default=0, nullable=False)
    vul_all_totales =  db.Column(db.Integer, default=0, nullable=False)

class Reportes_vulnerabilidades_url(db.Model):
    __tablename__ = 'reportes_vulnerabilidades_url'  
    
    id =  id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False)
    vul_altas = db.Column(db.Integer, default=0, nullable=False)
    vul_medias = db.Column(db.Integer, default=0, nullable=False)
    vul_bajas = db.Column(db.Integer, default=0, nullable=False)
    vul_info = db.Column(db.Integer, default=0, nullable=False)
    fecha_scan = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    report_file = db.Column(JSON, nullable=True)

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
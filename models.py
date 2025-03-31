from extensions import db
from datetime import datetime, timezone
from sqlalchemy import JSON, Index
import enum

# Enums para valores predefinidos
class EstadoEnum(enum.Enum):
    PENDIENTE = "PENDIENTE"
    COMPLETADO = "COMPLETADO"
    FALLIDO = "FALLIDO"
    EN_PROGRESO = "EN_PROGRESO"

class IntensidadEnum(enum.Enum):
    DEFAULT = "DEFAULT"
    BAJA = "LOW"
    MEDIA = "MEDIUM"
    ALTA = "HIGH"
    INSANE = "INSANE"

def get_utc_now():
    """Función helper para obtener la fecha UTC actual de forma consistente"""
    return datetime.now(timezone.utc)

class Escaneres_completados(db.Model):
    __tablename__ = 'escaneos_completados'  

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False, index=True)
    estado = db.Column(db.String(50), nullable=False)
    fecha_inicio = db.Column(db.DateTime(timezone=True), default=get_utc_now)
    fecha_fin = db.Column(db.DateTime(timezone=True), default=get_utc_now)
    intensidad = db.Column(db.String(50), nullable=False, default='DEFAULT')
    api_scan = db.Column(db.Boolean, default=False)
    api_file = db.Column(JSON, nullable=True)
    #report_file = db.Column(JSON, nullable=True) # recoger alertas que umbral medio/alto

    __table_args__ = (
        Index('idx_target_url_estado', 'target_url', 'estado'),
    )

class Vulnerabilidades_totales(db.Model):
    __tablename__ = 'vulnerabilidades_totales'  

    id = db.Column(db.Integer, primary_key=True)
    escaneos_totales = db.Column(db.Integer, default=0, nullable=False)
    vul_tot_altas = db.Column(db.Integer, default=0, nullable=False)
    vul_tot_medias = db.Column(db.Integer, default=0, nullable=False)
    vul_tot_bajas = db.Column(db.Integer, default=0, nullable=False)
    vul_tot_info = db.Column(db.Integer, default=0, nullable=False)
    vul_all_totales = db.Column(db.Integer, default=0, nullable=False)

class Reportes_vulnerabilidades_url(db.Model):
    __tablename__ = 'reportes_vulnerabilidades_url'  
    
    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False, index=True)
    vul_altas = db.Column(JSON, nullable=True)
    vul_medias = db.Column(JSON, nullable=True)
    vul_bajas = db.Column(JSON, nullable=True)
    vul_info = db.Column(JSON, nullable=True)
    fecha_scan = db.Column(db.DateTime(timezone=True), default=get_utc_now)
    report_file = db.Column(JSON, nullable=True)

    __table_args__ = (
        Index('idx_fecha_scan', 'fecha_scan'),
    )

class Escaneo_programados(db.Model):
    __tablename__= 'escaneos_programados'

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False, index=True)
    intensidad = db.Column(db.String(50), nullable=False, default='DEFAULT')
    fecha_programada = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    estado = db.Column(db.String(50), nullable=False, default='PENDIENTE')
    archivo_subido = db.Column(db.String(200), nullable=True)
    api_scan = db.Column(db.Boolean, default=False)
    api_file = db.Column(JSON, nullable=True)
    email = db.Column(db.String(120), nullable=False, server_default='gizquierdog@cofares.es')
    periodicidad_dias = db.Column(db.Integer, default=0)

    __table_args__ = (
        Index('idx_estado_fecha', 'estado', 'fecha_programada'),
    )

from extensions import db
from datetime import datetime

class Escaneres_completados(db.Model):
    __tablename__ = 'escaneos_completados'  

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(200), nullable=False)
    estado = db.Column(db.String(50), nullable=False)
    fecha_inicio = db.Column(db.DateTime, default=datetime.utcnow)
    fecha_fin = db.Column(db.DateTime, default=datetime.utcnow)
    intensidad = db.Column(db.String(50), nullable=False, default='DEFAULT')
    
    # Relación con la tabla Vulnerabilidades
    vulnerabilidades = db.relationship('Vulnerabilidades', backref='escaneo', lazy=True)

class Vulnerabilidades(db.Model):
    __tablename__ = 'vulnerabilidades'  

    id = db.Column(db.Integer, primary_key=True)
    escaneo_id = db.Column(db.Integer, db.ForeignKey('escaneos_completados.id'), nullable=False)
    severidad = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    url_afectada = db.Column(db.String(200), nullable=False)

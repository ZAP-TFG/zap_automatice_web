import json
from flask import Flask
from models import db, Reportes_vulnerabilidades_url  # Importa tu modelo y base de datos

def update_latest_report_file(json_path):
    try:
        with open(json_path, 'r', encoding='utf-8') as file:
            new_report_data = json.load(file)
    except Exception as e:
        print(f"Error al cargar el archivo JSON: {e}")
        return

    with app.app_context():
        latest_report = Reportes_vulnerabilidades_url.query.order_by(Reportes_vulnerabilidades_url.fecha_scan.desc()).offset(1).first()
        if latest_report:
            latest_report.report_file = new_report_data
            db.session.commit()
            print(f"El campo 'report_file' del último reporte (ID {latest_report.id}) fue actualizado correctamente.")
        else:
            print("No se encontró ningún reporte en la base de datos.")

if __name__ == "__main__":
    
    from app import app  
    from models import db, Reportes_vulnerabilidades_url  

    with app.app_context():
        # Actualiza el último reporte
        update_latest_report_file(
            json_path='/home/kalilinux22/Documents/2025-01-27-ZAP-Prueba_chatgpt_original2.json'
        )

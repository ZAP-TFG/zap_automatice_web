import os
import time
import json
import base64
import logging
import requests
from zapv2 import ZAPv2
from datetime import datetime
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email import encoders
from extensions import db
import smtplib
from models import Escaneres_completados, Vulnerabilidades_totales, Reportes_vulnerabilidades_url
from generate_report import generar_reporte_custom



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[ logging.StreamHandler(),logging.FileHandler("zap_logs.log", mode="w", encoding="utf-8")]
)

load_dotenv()

def connect_to_zap():
    try:
        zap = ZAPv2(apikey=os.getenv("ZAP_API_KEY"), proxies={'http': os.getenv("ZAP_URL")})
        logging.info(zap.core.version)
        return zap
    except Exception as error:
        logging.error(f"Error connecting to ZAP API: {error}")
        exit(1)

        
def add_url_to_sites(zap, url):
    try:
        if url not in zap.core.sites:
            zap.core.access_url(url)
            time.sleep(1)
        else:
            zap.core.new_session(name='nueva_sesion', overwrite=True)
            logging.info("Nueva sesión creada.")
            zap.core.access_url(url)
            time.sleep(1)
    except Exception as error:
        logging.error(f"Error adding URL to sites: {error}")
        exit(1)


def configure_scan_strength(zap, strength):
    try:
        for policy_id in range(5):
            zap.ascan.set_policy_attack_strength(policy_id, strength.upper())
            zap.ascan.set_policy_alert_threshold(policy_id, 'DEFAULT')

        policies = zap.ascan.policies()
        if all(policy['attackStrength'] == strength.upper() for policy in policies):
            logging.info("Attack strength configured.")
        else:
            raise Exception("Attack strength configuration mismatch.")
    except Exception as error:
        logging.error(f"Error configuring scan strength: {error}")
        exit(1)


def generate_report(zap, url):
    try:
        report_dir = os.getenv("REPORT_DIR", "./reportes")
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        report_filename = 'Reporte_vulnerabilidades.json'
        filepath = os.path.join(report_dir, report_filename)

        zap.reports.generate(
            title="report_json",
            template="traditional-json",
            sites=url,
            reportdir=report_dir,
            reportfilename=report_filename
        )

        with open(filepath, 'r') as file:
            report_content = json.load(file)

        os.remove(filepath)
        return report_content

    except Exception as e:
        logging.error(f"Error generating or reading report: {str(e)}")
        return None

def generar_reporte_custom_tabla_url(zap, url):
    try:
    # Configuración de ZAP

        end_date = datetime.now()

        # PASO 1: Generar el reporte JSON desde ZAP
        report_dir = "/app/reportes"
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)

        report_filename = 'Reporte_vulnerabilidades_otro.json'
        filepath = os.path.join(report_dir, report_filename)

        zap.reports.generate(
            title="report_json",
            template="traditional-json",
            sites=url,
            reportdir=report_dir,
            reportfilename=report_filename
        )

        # Cargar el reporte generado
        with open(filepath, 'r', encoding='utf-8') as file:
            json_data = json.load(file)

        # Eliminar el archivo temporal
        os.remove(filepath)

        # PASO 2: Buscar el sitio objetivo en el reporte
        target_host = "cfrsxnrtpre.cofares.es"
        site_data = None

        for site in json_data.get('site', []):
            if site.get('@host') == target_host:
                site_data = site
                break

        if not site_data:
            print(f"❌ No se encontró el sitio {target_host} en el reporte")
            exit()

        # PASO 3: Procesar las alertas del JSON
        alerts = site_data.get('alerts', [])

        # Configuración para ordenar y traducir riesgos
        risk_translation = {
            "High": "Alto",
            "Medium": "Medio", 
            "Low": "Bajo",
            "Informational": "Informativo"
        }

        # Conjuntos para evitar duplicados
        alertas_set = set()

        # Estructura para JSON agrupado por riesgo
        alertas_por_riesgo = {
            "high": [],
            "medium": [],
            "low": [],
            "informational": []
        }

        for alert in alerts:
            alert_name = alert.get('name', alert.get('alert', ''))
            
            # Extraer nivel de riesgo del riskdesc
            riskdesc = alert.get('riskdesc', 'Informational')
            
            # Normalizar nivel de riesgo desde riskdesc
            if 'Alto' in riskdesc or 'High' in riskdesc:
                risk_normalizado = 'High'
                risk_key = 'high'
            elif 'Medio' in riskdesc or 'Medium' in riskdesc:
                risk_normalizado = 'Medium'
                risk_key = 'medium'
            elif 'Bajo' in riskdesc or 'Low' in riskdesc:
                risk_normalizado = 'Low'
                risk_key = 'low'
            else:
                risk_normalizado = 'Informational'
                risk_key = 'informational'
            
            # Evitar duplicados
            if alert_name in alertas_set:
                continue
            
            alertas_set.add(alert_name)
            
            # PASO 4: Extraer attack y evidence de las instances
            attack = ""
            evidence = ""
            
            instances = alert.get('instances', [])
            if instances:
                # Tomar de la primera instancia que tenga datos
                for instance in instances:
                    if not attack and instance.get('attack'):
                        attack = instance.get('attack', '')
                    if not evidence and instance.get('evidence'):
                        evidence = instance.get('evidence', '')
                    # Si ya tenemos ambos, no necesitamos seguir buscando
                    if evidence and attack:
                        break
                
                # Si no encontramos attack/evidence, tomar de la primera instancia
                if not attack and not evidence and instances:
                    first_instance = instances[0]
                    attack = first_instance.get('attack', '')
                    evidence = first_instance.get('evidence', '')
            
            # Contar todas las instancias de esta alerta
            count = len(instances)
            
            # Crear datos de la alerta
            alerta_data = {
                "name": alert_name,
                "confidence": alert.get('confidence', ''),
                "riskdesc": alert.get('riskdesc', risk_normalizado),
                "risk_spanish": risk_translation.get(risk_normalizado, risk_normalizado),
                "desc": alert.get('desc', ''),
                "cweid": alert.get('cweid', ''),
                "reference": alert.get('reference', ''),
                "count": count,
                "attack": attack,
                "evidence": evidence
            }
            
            # Agregar a la categoría correspondiente
            alertas_por_riesgo[risk_key].append(alerta_data)

        # PASO 5: Crear JSON final procesado
        custom_report_file = {
            "target_url": site_data.get('@name', url),
            "target_host": site_data.get('@host', ''),
            "scan_date": end_date.isoformat(),
            "zap_version": json_data.get('@version', ''),
            "generated": json_data.get('@generated', ''),
            "total_alerts": len(alertas_set),
            "summary": {
                "high": len(alertas_por_riesgo["high"]),
                "medium": len(alertas_por_riesgo["medium"]),
                "low": len(alertas_por_riesgo["low"]),
                "informational": len(alertas_por_riesgo["informational"])
            },
            "alertas": alertas_por_riesgo
        }

        # PASO 6: Guardar en la base de datos
        scan_url = Reportes_vulnerabilidades_url(target_url=url, report_file=custom_report_file)
        db.session.add(scan_url)
        db.session.commit()

        # print(f"✅ Reporte procesado y guardado en base de datos para {url}")
        # print(f"Total alertas únicas procesadas: {len(alertas_set)}")
        # print(f"Alto: {len(alertas_por_riesgo['high'])}, Medio: {len(alertas_por_riesgo['medium'])}, Bajo: {len(alertas_por_riesgo['low'])}, Info: {len(alertas_por_riesgo['informational'])}")
    except Exception as e:
        logging.error(f"❌ Error procesando el reporte y creando el nuevo: {e}")
        

def update_total_vulnerabilities(high, medium, low, info):
    try:
        vul_total = Vulnerabilidades_totales.query.first()
        if not vul_total:
            vul_total = Vulnerabilidades_totales(escaneos_totales=0, vul_all_totales=0, vul_tot_altas=0, vul_tot_medias=0, vul_tot_bajas=0, vul_tot_info=0)
            db.session.add(vul_total)

        vul_total.escaneos_totales += 1
        vul_total.vul_all_totales += high + medium + low + info
        vul_total.vul_tot_altas += high
        vul_total.vul_tot_medias += medium
        vul_total.vul_tot_bajas += low
        vul_total.vul_tot_info += info

        db.session.commit()

    except Exception as e:
        logging.error(f"Error updating vulnerabilities totals: {e}")

        

def extract_vulnerabilities(zap, url, end_date):
    try:
        alerts = zap.alert.alerts(baseurl=url, start=0, count=500)
        vul_dict = {"High": set(), "Medium": set(), "Low": set(), "Info": set()}

        for alert in alerts:
            vul_dict.get(alert.get('risk', 'Info'), vul_dict['Info']).add(alert.get('name'))

        report = generate_report(zap, url)

        report_vuln = Reportes_vulnerabilidades_url(
            target_url=url,
            vul_altas=list(vul_dict["High"]),
            vul_medias=list(vul_dict["Medium"]),
            vul_bajas=list(vul_dict["Low"]),
            vul_info=list(vul_dict["Info"]),
            fecha_scan=end_date,
            report_file=report
        )
        db.session.add(report_vuln)
        db.session.commit()

        update_total_vulnerabilities(
            len(vul_dict["High"]), len(vul_dict["Medium"]),
            len(vul_dict["Low"]), len(vul_dict["Info"])
        )

    except Exception as e:
        logging.error(f"Error extracting vulnerabilities: {e}")


def perform_scan(zap, url, strength):
    configure_scan_strength(zap, strength)
    try:
        scan = Escaneres_completados(target_url=url, estado="En proceso", fecha_inicio=datetime.now(), intensidad=strength, progreso = 0)
        db.session.add(scan)
        db.session.commit()

        scan_id = zap.ascan.scan(url)
        start_time = time.time()
        timeout = 10800
        while int(zap.ascan.status(scan_id)) < 100:
            if (time.time() - start_time) > timeout:
                logging.error("Timeout exceeded.")
                break
            progreso = zap.ascan.status(scan_id)
            logging.info(f"Scan Progress: {progreso}%")
            scan.progreso = progreso
            db.session.commit()
            time.sleep(2)
        scan.progreso = 100
        db.session.commit()
        time.sleep(1)
        scan.fecha_fin = datetime.now()
        scan.report_file = generate_report(zap, url)
        scan.estado = "COMPLETADO"
        db.session.commit()

        extract_vulnerabilities(zap, url, scan.fecha_fin)
        generar_reporte_custom_tabla_url(zap, url)
        return scan_id

    except Exception as error:
        logging.error(f"Error during scan {url}: {error}")
        exit(1)

def perform_plan_automation(zap,url,file_path, email):
    """
    Ejecuta un plan de automatización en ZAP.
    """
    try:
        api_url = os.getenv("ZAP_URL")
        api_key = os.getenv("ZAP_API_KEY")
        headers = {
            'Accept': 'application/json'
        }

        file_path_complete =  f"/zap/yaml_files/{file_path}" 

        r = requests.get(f'{api_url}/JSON/automation/action/runPlan/', params={
            'apikey': api_key,
            'filePath': file_path_complete
        }, headers=headers)
        planID = r.json().get('planId')
        if not planID:
            logging.error("No se pudo obtener el ID del plan de automatización.\n")
        logging.info(f"Ejecutandose el plan: {planID}")

        scan = Escaneres_completados(target_url=url, estado="En proceso", fecha_inicio=datetime.now(), progreso = 0, yaml_file_path=file_path_complete, email=email)
        db.session.add(scan)
        db.session.commit()
        while True:
            headers = {
                'Accept': 'application/json'
            }

            r = requests.get(f'{api_url}/JSON/automation/view/planProgress/', params={
            'planId': planID, 'apikey': api_key}, 
            headers = headers)
            json_parsed = r.json()
            if json_parsed.get('finished') == '':
                logging.info(f"Plan ID: {planID} - en progreso.\n")
            else:
                logging.info(f"Plan ID: {planID} - finalizado.\n")
                break
            time.sleep(2)

        scan.fecha_fin = datetime.now()
        scan.report_file = generate_report(zap, url)
        scan.estado = "COMPLETADO"
        db.session.commit()
        extract_vulnerabilities(zap, url, scan.fecha_fin)
            
    except Exception as e:
        logging.error(f"Error executing automation plan: {e}")
        exit(1)


def send_email(zap, url, email):
    docx_path = generar_reporte_custom(url)

    alerts = zap.alert.alerts(baseurl=url, start=0, count=500)
    vul_dict = {"High": set(), "Medium": set(), "Low": set()}

    for alert in alerts:
        alert_risk = alert.get('risk')
        alert_name = alert.get('name')
        if alert_risk in vul_dict:
            vul_dict[alert_risk].add(alert_name)

    # Crear contenido HTML
    email_content = f"""
    <html>
        <body>
            <p>El escáner ha finalizado para: <strong>{url}</strong></p>
            <hr>
            <p><strong>Resumen de vulnerabilidades:</strong></p>
            <ul>
                <li><strong>Altas:</strong> {len(vul_dict['High'])}</li>
                <li><strong>Medias:</strong> {len(vul_dict['Medium'])}</li>
                <li><strong>Bajas:</strong> {len(vul_dict['Low'])}</li>
            </ul>
    """

    for level in ["High", "Medium", "Low"]:
        if vul_dict[level]:
            email_content += f"<p><strong>Vulnerabilidades {level}:</strong></p><ul>"
            for alert in vul_dict[level]:
                email_content += f"<li>{alert}</li>"
            email_content += "</ul>"

    email_content += "</body></html>"

    # Configurar email
    sender_address = "vulnstorm@cofares.es"
    receiver_address = email

    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = f'Escaner Finalizado para: {url}'

    # Adjuntar HTML
    message.attach(MIMEText(email_content, 'html'))

    # Adjuntar documento .docx
    try:
        with open(docx_path, "rb") as doc_file:
            attachment = MIMEApplication(doc_file.read(), _subtype="vnd.openxmlformats-officedocument.wordprocessingml.document")
            attachment.add_header('Content-Disposition', 'attachment', filename=os.path.basename(docx_path))
            message.attach(attachment)
    except Exception as e:
        logging.error(f"No se pudo adjuntar el documento: {e}")
        return

    # Enviar correo vía SMTP relay
    try:
        session = smtplib.SMTP('192.0.1.252', 25)
        session.sendmail(sender_address, [receiver_address], message.as_string())
        session.quit()
        logging.info("Correo enviado con éxito.")
    except Exception as e:
        logging.error(f"Error al enviar correo: {e}")





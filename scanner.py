from zapv2 import ZAPv2
import time
import logging
from dotenv import load_dotenv
import os
from extensions import *
from models import *
import json
import requests
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

#variable global
SCANER_ID = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("zap_logs.log", mode="w", encoding="utf-8")
    ]
)

load_dotenv()

def connection_to_zap():
    try:
        zap = ZAPv2(apikey=os.getenv("ZAP_API_KEY"), proxies={'http': 'http://localhost:8081'})#
        logging.info(zap.core.version)
        return zap
    except Exception as error:
        logging.error(f"Error trying to connect to API: {error}")
        exit(1)

def is_in_sites(zap,url):
    try:
        sites = zap.core.sites
        if url not in sites:
           zap.core.access_url(url)
           time.sleep(1)
           #is_in_sites(zap,url)
        else:
            zap.core.new_session(name='nueva_sesion', overwrite=True)
            logging.info("Nueva sesion...")
            time.sleep(2)
            zap.core.access_url(url)
            time.sleep(1)
            
    except Exception as error:
        logging.error(f"Error trying to add URL in Sites: {error}")
        exit(1)

def scan_strength(zap,strength):
    count = 0
    try:
        for policy_id in range(5):
            zap.ascan.set_policy_attack_strength(policy_id, strength.upper())
            zap.ascan.set_policy_alert_threshold(policy_id, 'DEFAULT')

        scan_info_strength = zap.ascan.policies()
        time.sleep(2)
        for policy in scan_info_strength:
            if policy['attackStrength'] == strength.upper():
                count+=1
        if count == 5:
            logging.info("Attack_Strength Configured")
        else:
            logging.error("Attack Strength NOT Configured")
            raise
    except Exception as error:
        logging.error(f"Error trying to set scan strength: {error}")
        exit(1)


def get_report(zap, url):
    try:
        reportdir = '/tmp'
        reportfilename = 'Reporte_vulnerabilidades'
        filepath = os.path.join(reportdir, f"{reportfilename}.json")
        zap.reports.generate(
            title="report_json",
            template="traditional-json",
            sites=url,
            reportdir=reportdir,
            reportfilename=reportfilename
        )
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"El archivo de reporte no se encontró en la ruta esperada: {filepath}")
        with open(filepath, 'r') as file:
            report_content = json.load(file)
        os.remove(filepath)
        return report_content

    except Exception as e:
        logging.error(f"Error al generar o leer el reporte: {str(e)}")
        return None

def get_total_vulnerabilities(high, medium, low, info):
    try: 
        vulne_totales = Vulnerabilidades_totales.query.first()
        if vulne_totales:
            vulne_totales.escaneos_totales += 1
            vulne_totales.vul_all_totales += high + medium + low + info
            vulne_totales.vul_tot_altas += high                    
            vulne_totales.vul_tot_medias += medium            
            vulne_totales.vul_tot_bajas += low                     
            vulne_totales.vul_tot_info += info     
        else:
            vulnerabilidades_totales = Vulnerabilidades_totales(
                escaneos_totales = 1,
                vul_all_totales = high + medium + low + info,
                vul_tot_altas = high,
                vul_tot_medias = medium,
                vul_tot_bajas =low,
                vul_tot_info = info
            )
            db.session.add(vulnerabilidades_totales)

        db.session.commit()

    except Exception as e:
        logging.error(f"Error al actualizar los totales de vulnerabilidades: {e}")
        

def get_vulnerabilities(zap,url,fecha_fin):
    st = 0
    max = 500
    alerts_high = set()
    alerts_medium = set()
    alerts_low = set()
    alerts_info = set()
    try:
        alerts = zap.alert.alerts(baseurl = url, start = st, count=max)
        for alert in alerts:
            alert_risk = alert.get('risk')
            alert_name = alert.get('name')
            if alert_risk == 'High':
                alerts_high.add(f"{alert_name}")
            elif alert_risk == 'Medium':
                alerts_medium.add(f"{alert_name}")
            elif alert_risk == 'Low':
                alerts_low.add(f"{alert_name}")
            else:
                alerts_info.add(f"{alert_name}")
        report = get_report(zap,url)
        time.sleep(2)
        reportes_vulnnerabilidades = Reportes_vulnerabilidades_url(
            target_url = url,
            vul_altas = len(alerts_high),
            vul_medias = len(alerts_medium),
            vul_bajas = len(alerts_low),
            vul_info = len(alerts_info),
            fecha_scan = fecha_fin,
            report_file = report
        )
        db.session.add(reportes_vulnnerabilidades)
        db.session.commit()
        get_total_vulnerabilities(len(alerts_high), len(alerts_medium),len(alerts_low),len(alerts_info))

    except Exception as e:
        logging.error(f"Error al tratar de genererar vulenrabilidades: {e}")


def active_scan(zap,url,strength):
    scan_strength(zap,strength)
    time.sleep(1)
    try:
        fecha_ini = datetime.now()
        escaneo_completado = Escaneres_completados(
            target_url = url,
            estado = "En proceso",
            fecha_inicio = fecha_ini,
            intensidad = strength
        )
        #zap.core.new_session(name="sesion_unica", overwrite=True)
        time.sleep(2) ############################################################3
        scan_id = zap.ascan.scan(url)
        
        while True:
            if int(zap.ascan.status(scan_id)) < 100:
                logging.info(f"Scan Progress: {zap.ascan.status(scan_id)}")
                time.sleep(2)
            elif int(zap.ascan.status(scan_id)) == 100:
                logging.info("Scan Complete -> 100%")
                break
        report_file = get_report(zap,url)
        fecha_fin = datetime.now()
        escaneo_completado.fecha_fin = fecha_fin
        escaneo_completado.report_file = report_file
        escaneo_completado.estado = "COMPLETADO"
        db.session.add(escaneo_completado)
        db.session.commit()
        get_vulnerabilities(zap,url,fecha_fin)
        SCANER_ID = scan_id
        return scan_id
        
    except Exception as error:
        logging.error(f"Error trying to Scan {url}: {error}")
        exit(1)
    




def send_email(zap,url,email):
#####################################################################################
#####                       REPORTAR ALERTAS ALTAS Y MEDIAS               ###########
#####################################################################################
    # status = 0
    # while True:
    #     status = zap.ascan.status(SCANER_ID)
    #     if status == 100:
    #         break
    # if status == 100:
    alerts_high = set() 
    alerts_medium = set()  
    alerts_low = set()

    st = 0
    pg = 5000
    alerts = zap.alert.alerts(baseurl=url, start=st, count=pg)

    for alert in alerts:
        alert_risk = alert.get('risk')
        alert_name = alert.get('alert')

        if alert_risk == 'High':
            alerts_high.add(alert_name)  
        elif alert_risk == 'Medium':
            alerts_medium.add(alert_name)
        elif alert_risk == 'Low':
            alerts_low.add(alert_name)
    #####################################################################################
    #####                             GENERAR REPORTE                         ###########
    #####################################################################################
    report_path = '/tmp'
    reporte = zap.reports.generate(
        title='reporte_vulnerabilidades',
        template='traditional-pdf',  
        sites=url,               
        reportdir=report_path,
        reportfilename='reporte_vulnerabilidades' 
    )

    #####################################################################################
    #####                   MANDAR CORREO UNA VEZ FINALIZADO                  ###########
    #####################################################################################

    # Función para enviar el correo usando SendGrid

    sendgrid_url = "https://api.sendgrid.com/v3/mail/send"
    sendgrid_api_key = "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"

    email_content = f"""
    <html>
        <body>
            <p><strong>El escáner ha finalizado para las siguientes URLs:</strong></p>
            <ul>
                <li>{url}</li>
            </ul>
            <hr>
            <p><strong>Resumen de vulnerabilidades encontradas:</strong></p>
            <ul>
                <li><strong>ALTAS:</strong> {len(alerts_high)}</li>
                <li><strong>MEDIAS:</strong> {len(alerts_medium)}</li>
                <li><strong>BAJAS:</strong> {len(alerts_low)}</li>
            </ul>
    """

    if alerts_high:
        email_content += """
            <p><strong>Lista de alertas ALTAS:</strong></p>
            <ul>
        """
        for alert in alerts_high:
            email_content += f"<li>{alert}</li>"
        email_content += "</ul>"

    if alerts_medium:
        email_content += """
            <p><strong>Lista de alertas MEDIAS:</strong></p>
            <ul>
        """
        for alert in alerts_medium:
            email_content += f"<li>{alert}</li>"
        email_content += "</ul>"
    
    if alerts_low:
        email_content += """
            <p><strong>Lista de alertas MEDIAS:</strong></p>
            <ul>
        """
        for alert in alerts_low:
            email_content += f"<li>{alert}</li>"
        email_content += "</ul>"

    email_content += """
        </body>
    </html>
    """

    # Crear el objeto de mensaje MIME para incluir el archivo adjunto
    msg = MIMEMultipart()
    msg['From'] = "zapautomatic3@gmail.com"
    msg['To'] = f"{email}"
    msg['Subject'] = f"Escáner finalizado para la URL: {url}"
    msg.attach(MIMEText(email_content, 'html'))

    path_pdf = os.path.join(report_path, "reporte_vulnerabilidades.pdf")
    # Abrir el archivo PDF generado y adjuntarlo
    with open(path_pdf, "rb") as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f"attachment; filename={os.path.basename(path_pdf)}")
        msg.attach(part)


    # Configurar los datos para SendGrid
    email_data = {
        "personalizations": [
            {
                "to": [{"email": f"{email}"}],
                "subject": f"Escáner finalizado para la URL: {url}"
            }
        ],
        "from": {
            "email": "zapautomatic3@gmail.com"
        },
        "content": [
            {
                "type": "text/html",
                "value": email_content
            }
        ],
        "attachments": [
            {
                "content": base64.b64encode(open(path_pdf, "rb").read()).decode(),
                "type": "application/pdf",
                "filename": os.path.basename(path_pdf)
            }
        ]
    }

    # Cabeceras para autenticación con SendGrid
    headers = {
        "Authorization": f"Bearer {sendgrid_api_key}",
        "Content-Type": "application/json"
    }

    # Solicitud POST para enviar el correo
    response = requests.post(sendgrid_url, headers=headers, data=json.dumps(email_data))

    # Verificar respuesta
    if response.status_code == 202:
        print("Correo enviado con éxito.")
    else:
        print(f"Error al enviar el correo. Código de respuesta: {response.status_code}")
        print(response.text)



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
from email.mime.base import MIMEBase
from email import encoders
from extensions import db
from models import Escaneres_completados, Vulnerabilidades_totales, Reportes_vulnerabilidades_url
from generate_report import generar_reporte_custom
import urllib.parse


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

def autentication_zap(zap,url):    
    target_url = f"{url}/start.mvc?username=gabrito#lesson/WebGoatIntroduction.lesson"
    login_url = f"{url}/login"
    username_field = 'username'
    password_field = 'password'
    username = 'gabrito'
    password = 'gabrito'
    context_name = 'webgoat'
    logged_in_indicator = 'Welcome gabrito!'
    logged_out_indicator = 'Invalid username and password'
    ZAP_URL = os.getenv("ZAP_URL")
    proxies = {'http': ZAP_URL}

    contexts = zap.context.context_list
    if context_name in contexts:
        info = zap.context.context(context_name)
        context_id = int(info['id'])
        print(f"Usando contexto existente: {context_name} (ID: {context_id})")
    else:
        context_id = zap.context.new_context(context_name)
        print(f"Creado nuevo contexto: {context_name} (ID: {context_id})")

    # Incluir todo el sitio en el contexto
    zap.context.include_in_context(context_name, rf"{url}.*")

    # --- Configurar autenticación de formulario ---
    login_data = urllib.parse.quote_plus(
        f"{username_field}={{%username%}}&{password_field}={{%password%}}"
    )
    auth_params = (
        f"loginUrl={login_url}"
        f"&loginRequestData={login_data}"
    )
    zap.authentication.set_authentication_method(
        context_id,
        'formBasedAuthentication',
        auth_params
    )
    zap.authentication.set_logged_in_indicator(context_id, logged_in_indicator)
    zap.authentication.set_logged_out_indicator(context_id, logged_out_indicator)
    print("Método de autenticación configurado")

    # --- Comprobar o crear usuario ---
    user_id = None
    for uid in zap.users.users_list(contextid=context_id):
        user_info = zap.users.get_user_by_id(context_id, uid)
        if user_info.get('name') == username:
            user_id = uid
            print(f"Usuario existente encontrado: {username} (ID: {user_id})")
            break
    if not user_id:
        user_id = zap.users.new_user(context_id, username)
        zap.users.set_user_enabled(context_id, user_id, True)
        print(f"Nuevo usuario creado: {username} (ID: {user_id})")
    # Establecer credenciales
    zap.users.set_authentication_credentials(
        context_id,
        user_id,
        f"{username_field}={username}&{password_field}={password}"
    )
    print("Credenciales de usuario configuradas")

    # --- Modo usuario forzado ---
    zap.forcedUser.set_forced_user(context_id, user_id)
    zap.forcedUser.set_forced_user_mode_enabled(True)
    print("Forced User Mode habilitado")

    # --- Realizar login vía POST a través de ZAP proxy ---
    print(f"Autenticando usuario {username} con POST al proxy de ZAP...")
    try:
        r = requests.post(
            login_url,
            data={username_field: username, password_field: password},
            proxies=proxies,
            allow_redirects=True
        )
        print(f"Login HTTP status: {r.status_code}")
        # Esperar a que ZAP capture cookies
        time.sleep(2)
    except Exception as e:
        print(f"Error durante POST de login: {e}")
        

    # --- Spider autenticado ---
    print(f"Iniciando spider autenticado sobre {target_url}...")
    scan_id = zap.spider.scan_as_user(
        contextid=context_id,
        userid=user_id,
        url=target_url
    )
    # Monitorear progreso
    while True:
        pct = int(zap.spider.status(scan_id))
        print(f"Spider progreso: {pct}%")
        if pct >= 100:
            break
        time.sleep(2)
    print("Spider completado")

    # --- Esperar passive scan ---
    print("Esperando passive scan...")
    while int(zap.pscan.records_to_scan) > 0:
        print(f"Pendientes passive scan: {zap.pscan.records_to_scan}")
        time.sleep(2)
    print("Passive scan completado")

    # --- Active scan autenticado ---
    print(f"Iniciando active scan autenticado sobre {target_url}...")
   
    return context_id, user_id, target_url

def perform_scan(zap, url, strength):
    configure_scan_strength(zap, strength)
    try:
        scan = Escaneres_completados(target_url=url, estado="En proceso", fecha_inicio=datetime.now(), intensidad=strength, progreso = 0)
        db.session.add(scan)
        db.session.commit()

        context_id, user_id, target_url = autentication_zap(zap,url)
        scan_id =  zap.ascan.scan_as_user(
        contextid=context_id,
        userid=user_id,
        url=target_url
        )
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

        return scan_id

    except Exception as error:
        logging.error(f"Error during scan {url}: {error}")
    
    



def send_email(zap, url, email):
    docx_path = generar_reporte_custom(url)

    alerts = zap.alert.alerts(baseurl=url, start=0, count=500)
    vul_dict = {"High": set(), "Medium": set(), "Low": set()}

    for alert in alerts:
        alert_risk = alert.get('risk')
        alert_name = alert.get('name')
        if alert_risk in vul_dict:
            vul_dict[alert_risk].add(alert_name)

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

    sendgrid_api_key = os.getenv("SENDGRID_API_KEY")

    email_data = {
        "personalizations": [{"to": [{"email": email}], "subject": f"Escáner finalizado: {url}"}],
        "from": {"email": "zapautomatic8@gmail.com"},
        "content": [{"type": "text/html", "value": email_content}],
        "attachments": [{
            "content": base64.b64encode(open(docx_path, "rb").read()).decode(),
            "type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "filename": os.path.basename(docx_path)
        }]
    }

    headers = {"Authorization": f"Bearer {sendgrid_api_key}", "Content-Type": "application/json"}

    response = requests.post("https://api.sendgrid.com/v3/mail/send", headers=headers, data=json.dumps(email_data))

    if response.status_code == 202:
        logging.info("Correo enviado con éxito.")
    else:
        logging.error(f"Error al enviar correo: {response.status_code} - {response.text}")



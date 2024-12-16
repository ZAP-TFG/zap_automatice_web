from zapv2 import ZAPv2
import time
import logging
from dotenv import load_dotenv
import os
from extensions import *
from models import *
import json



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("zap_logs.log", mode="w", encoding="utf-8")
    ]
)
def load_env():
    load_dotenv()

def connection_to_zap():
    try:
        zap = ZAPv2(apikey=os.getenv("ZAP_API_KEY"),proxies={'http': 'http://127.0.0.1:8081'})
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
            pass
            logging.info("Url in Sites")
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
        return scan_id
        
    except Exception as error:
        logging.error(f"Error trying to Scan {url}: {error}")
        exit(1)
    


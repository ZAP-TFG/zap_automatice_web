from apscheduler.triggers.date import DateTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from app import app
from models import *
from datetime import datetime
from scanner import *
import logging
import os

# Configurar logging
for handler in logging.root.handlers[:]: #loggin.root.handler es una lista que contiene todos los manejadores asociados a root.logger y craa una copia de esa lista en la que vamos a ir modificandola a medida que vamos iterandola y este bucle itera sobre cada manejador de la lista manejadores
    logging.root.removeHandler(handler) # elimina el manejador actual del root logger.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuración del scheduler
jobstores = {'default': SQLAlchemyJobStore(url='sqlite:///jobs.db')}
scheduler = BackgroundScheduler(jobstores=jobstores)


def init_scheduler():
    try:
        if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':  # Sólo inicia en el proceso principal
            logger.info("Initializing scheduler...")
            scheduler.start()
            logger.info("Scheduler started")

            # Verificar si ya existe el trabajo antes de agregarlo
            if not scheduler.get_job('check_pending_scans'):
                scheduler.add_job(
                    check_for_pending_scans,
                    'interval',
                    minutes=10,
                    id='check_pending_scans',
                    misfire_grace_time=300,
                    max_instances=1
                )
                logger.info("Job para revisar escaneos pendientes agregado.")

            # Cargar trabajos pendientes desde la base de datos
            with app.app_context():
                scans = db.session.query(Escaneo_programados).filter_by(estado='PENDIENTE').all()
                for scan in scans:
                    add_scan_job(scan)
                logger.info(f"{len(scans)} trabajos cargados desde la base de datos.")

    except Exception as e:
        logger.error(f"Error while initializing scheduler: {e}")


def add_scan_job(scan, immediate_execution=False):
    try:
        if not scheduler.get_job(str(scan.id)):  # Solo agregar si no existe
            trigger = DateTrigger(run_date=scan.fecha_programada)
            job = scheduler.add_job(
                func=execute_scan,
                trigger=trigger,
                args=[scan.id],
                id=str(scan.id),
                misfire_grace_time=600
            )
            logger.info(f"Escaneo {scan.id} programado para {scan.fecha_programada}")

            if immediate_execution:  # Si la ejecución debe ser inmediata
                execute_scan(scan.id)
                job.remove()

        else:
            logger.info(f"Escaneo {scan.id} programado ya existe")

    except Exception as e:
        logger.error(f"Error al programar el escaneo {scan.id}: {e}")


def execute_scan(scan_id):
    try:
        with app.app_context():
            scan = db.session.query(Escaneo_programados).get(scan_id)
            if scan:
                scan.estado = "EN PROCESO"
                db.session.commit()
                logger.info(f"Comenzando escaneo para {scan.target_url} con intensidad {scan.intensidad}.")
                zap = connection_to_zap()
                is_in_sites(zap, scan.target_url)
                active_scan(zap, scan.target_url, scan.intensidad)
                scan.estado = 'COMPLETADO'
                db.session.commit()
            else:
                logger.warning(f"Escaneo con ID {scan_id} no encontrado.")

    except Exception as e:
        with app.app_context():
            scan = db.session.query(Escaneo_programados).get(scan_id)
            if scan:
                scan.estado = 'ERROR'
                db.session.commit()
        logger.error(f"Error al ejecutar el escaneo {scan_id}: {e}")


def check_for_pending_scans():
    try:
        with app.app_context():
            scans = db.session.query(Escaneo_programados).filter_by(estado='PENDIENTE').all()
            for scan in scans:
                if not scheduler.get_job(str(scan.id)):
                    add_scan_job(scan)
            logger.info(f"Se han revisado {len(scans)} escaneos pendientes.")
    except Exception as e:
        logger.error(f"Error al revisar escaneos pendientes: {e}")

from apscheduler.triggers.date import DateTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from extensions import *
from models import *
from datetime import datetime
from scanner import connect_to_zap, add_url_to_sites, perform_scan, send_email
import logging
import os
import threading

# Configurar logging
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuración del scheduler
jobstores = {'default': SQLAlchemyJobStore(url='sqlite:///jobs.db')}
scheduler = BackgroundScheduler(jobstores=jobstores)

scan_lock = threading.Lock()


def init_scheduler():
    """
    Inicializa el programador de tareas y carga trabajos pendientes desde la base de datos.
    """
    try:
        if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':  
            logger.info("Initializing scheduler...")
            scheduler.start()
            logger.info("Scheduler started")

            
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

            with app.app_context():
                scans = db.session.query(Escaneo_programados).filter_by(estado='PENDIENTE').all()
                for scan in scans:
                    add_scan_job(scan)
                logger.info(f"{len(scans)} trabajos cargados desde la base de datos.")

    except Exception as e:
        logger.error(f"Error while initializing scheduler: {e}")


def add_scan_job(scan, immediate_execution=False):
    """
    Agrega un trabajo de escaneo al programador.
    """
    try:
        if not scheduler.get_job(str(scan.id)): 
            trigger = DateTrigger(run_date=scan.fecha_programada)
            job = scheduler.add_job(
                func=execute_scan,
                trigger=trigger,
                args=[scan.id],
                id=str(scan.id),
                misfire_grace_time=10800,  
                max_instances=1  
            )
            logger.info(f"Escaneo {scan.id} programado para {scan.fecha_programada}")

            if immediate_execution: 
                execute_scan(scan.id)
                job.remove()

        else:
            logger.info(f"Escaneo {scan.id} ya está programado.")

    except Exception as e:
        logger.error(f"Error al programar el escaneo {scan.id}: {e}")


def execute_scan(scan_id):
    """
    Ejecuta un escaneo programado.
    """
    try:
        if not scan_lock.acquire(blocking=False):
            logger.warning(f"El escaneo {scan_id} no se puede ejecutar porque otro escaneo está en progreso.")
            return

        with app.app_context():
            scan = db.session.query(Escaneo_programados).get(scan_id)
            if scan:
                scan.estado = "EN PROCESO"
                db.session.commit()
                logger.info(f"Comenzando escaneo para {scan.target_url} con intensidad {scan.intensidad}.")

                zap = connect_to_zap()
                add_url_to_sites(zap, scan.target_url)
                perform_scan(zap, scan.target_url, scan.intensidad)

                scan.estado = 'COMPLETADO'
                db.session.commit()
                logger.info(f"Escaneo {scan_id} completado exitosamente.")

                # Enviar correo al finalizar el escaneo
                send_email(zap, scan.target_url, scan.email if hasattr(scan, 'email') else None)
            else:
                logger.warning(f"Escaneo con ID {scan_id} no encontrado.")

    except Exception as e:
        with app.app_context():
            scan = db.session.query(Escaneo_programados).get(scan_id)
            if scan:
                scan.estado = 'ERROR'
                db.session.commit()
        logger.error(f"Error al ejecutar el escaneo {scan_id}: {e}")

    finally:
        
        scan_lock.release()


def check_for_pending_scans():
    """
    Revisa los escaneos pendientes y los programa si no están ya en el programador.
    """
    try:
        with app.app_context():
            scans = db.session.query(Escaneo_programados).filter_by(estado='PENDIENTE').all()
            for scan in scans:
                if not scheduler.get_job(str(scan.id)):
                    add_scan_job(scan)
            logger.info(f"Se han revisado {len(scans)} escaneos pendientes.")
    except Exception as e:
        logger.error(f"Error al revisar escaneos pendientes: {e}")
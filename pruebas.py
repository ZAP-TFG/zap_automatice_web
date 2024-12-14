from zapv2 import ZAPv2
import time
import logging
from dotenv import load_dotenv
import os

#def load_env():
load_dotenv()

def connection_to_zap():
    try:
        zap = ZAPv2(apikey=os.getenv("ZAP_API_KEY"),proxies={'http': 'http://127.0.0.1:8081'})
        logging.info(zap.core.version)
        return zap
    except Exception as error:
        logging.error(f"Error trying to connect to API: {error}")
        exit(1)

url = 'http://example.com'
nombre = 'gabri'
zap = connection_to_zap()
# zap.core.new_session(name="sesion_unica", overwrite=True)
# time.sleep(2)
# zap.core.access_url(url)
# time.sleep(1)
# scan_id = zap.ascan.scan(url)
alerts = zap.alert.alerts_by_risk(url=url)
alerts_high = alerts.get('Informational')
print(alerts_high)
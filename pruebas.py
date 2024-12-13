from zapv2 import ZAPv2
import time
import logging
from dotenv import load_dotenv
import os

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

url = 'http://example.com'
nombre = 'gabri'
zap = connection_to_zap()
report_json = zap.reports.generate(
    title=nombre,
    template='traditional-json',
    sites=url
)
print(report_json)
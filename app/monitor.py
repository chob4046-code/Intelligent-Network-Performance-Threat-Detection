import socket
import threading
import time
from .db import targets, record_check, record_event, create_alert


def check_tcp(host, port, timeout=2):
    started=time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return 'UP', round((time.perf_counter()-started)*1000,2), None
    except (OSError, ValueError) as exc:
        return 'DOWN', None, str(exc)[:200]


def run_once(config):
    path=config['DB_PATH']
    for target in targets(path):
        if not target['enabled']: continue
        status, latency, error=check_tcp(target['host'], target['port'], config['CONNECT_TIMEOUT'])
        record_check(path,target['id'],status,latency,error)
        if status=='DOWN':
            record_event(path,'service_unreachable','warning',target['host'],f'{target["name"]} is unreachable on TCP/{target["port"]}')
            create_alert(path,'warning','Service unavailable',f'{target["name"]} ({target["host"]}:{target["port"]}) is DOWN')
        elif latency is not None and latency >= config['ANOMALY_LATENCY_MS']:
            record_event(path,'high_latency','warning',target['host'],f'{target["name"]} latency is {latency} ms')
            create_alert(path,'warning','High latency',f'{target["name"]} latency reached {latency} ms')


def start_monitor(config):
    def loop():
        while True:
            try: run_once(config)
            except Exception as exc: print(f'NetWatch monitor error: {exc}')
            time.sleep(max(5,int(config['MONITOR_INTERVAL'])))
    threading.Thread(target=loop,daemon=True,name='netwatch-monitor').start()

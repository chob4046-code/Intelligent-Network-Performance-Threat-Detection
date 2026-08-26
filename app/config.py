import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-only-change-me')
    ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'ChangeMe-StrongPassword')
    DB_PATH = os.getenv('DB_PATH', os.path.join(os.getcwd(), 'netwatch.db'))
    MONITOR_INTERVAL = int(os.getenv('MONITOR_INTERVAL', '30'))
    CONNECT_TIMEOUT = float(os.getenv('CONNECT_TIMEOUT', '2'))
    ANOMALY_LATENCY_MS = float(os.getenv('ANOMALY_LATENCY_MS', '500'))

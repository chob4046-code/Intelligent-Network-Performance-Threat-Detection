import time
from hashlib import sha256
from werkzeug.security import generate_password_hash, check_password_hash


def hash_password(password):
    return generate_password_hash(password)


def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)


def client_key(ip):
    return sha256((ip or 'unknown').encode()).hexdigest()[:32]


def now():
    return int(time.time())

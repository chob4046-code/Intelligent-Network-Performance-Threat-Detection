import sqlite3
from contextlib import contextmanager
from .security import hash_password, now

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS checks (id INTEGER PRIMARY KEY, target_id INTEGER NOT NULL, checked_at INTEGER NOT NULL, status TEXT NOT NULL, latency_ms REAL, error TEXT, FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, created_at INTEGER NOT NULL, event_type TEXT NOT NULL, severity TEXT NOT NULL, source TEXT, message TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, created_at INTEGER NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS login_attempts (id INTEGER PRIMARY KEY, client_key TEXT NOT NULL, success INTEGER NOT NULL, attempted_at INTEGER NOT NULL);
'''

@contextmanager
def connect(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        yield db
        db.commit()
    finally:
        db.close()


def init_db(path, username, password):
    with connect(path) as db:
        db.executescript(SCHEMA)
        if not db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
            db.execute('INSERT INTO users(username,password_hash) VALUES (?,?)', (username, hash_password(password)))


def get_user(path, username):
    with connect(path) as db:
        return db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()


def add_target(path, name, host, port):
    with connect(path) as db:
        cur = db.execute('INSERT INTO targets(name,host,port,created_at) VALUES (?,?,?,?)', (name,host,port,now()))
        return cur.lastrowid


def set_target_enabled(path, target_id, enabled):
    with connect(path) as db: db.execute('UPDATE targets SET enabled=? WHERE id=?', (int(enabled),target_id))


def delete_target(path, target_id):
    with connect(path) as db:
        db.execute('DELETE FROM checks WHERE target_id=?', (target_id,))
        db.execute('DELETE FROM targets WHERE id=?', (target_id,))


def targets(path):
    with connect(path) as db: return db.execute('SELECT * FROM targets ORDER BY name').fetchall()


def record_check(path, target_id, status, latency_ms, error):
    with connect(path) as db: db.execute('INSERT INTO checks(target_id,checked_at,status,latency_ms,error) VALUES (?,?,?,?,?)', (target_id,now(),status,latency_ms,error))


def latest_targets(path):
    with connect(path) as db:
        return db.execute('''SELECT t.*, c.status, c.latency_ms, c.checked_at, c.error FROM targets t LEFT JOIN checks c ON c.id=(SELECT id FROM checks WHERE target_id=t.id ORDER BY checked_at DESC LIMIT 1) ORDER BY t.name''').fetchall()


def recent_checks(path, target_id, limit=50):
    with connect(path) as db: return db.execute('SELECT * FROM checks WHERE target_id=? ORDER BY checked_at DESC LIMIT ?', (target_id,limit)).fetchall()


def record_event(path, event_type, severity, source, message):
    with connect(path) as db: db.execute('INSERT INTO events(created_at,event_type,severity,source,message) VALUES (?,?,?,?,?)', (now(),event_type,severity,source,message))


def recent_events(path, limit=50):
    with connect(path) as db: return db.execute('SELECT * FROM events ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()


def create_alert(path, severity, title, message):
    with connect(path) as db: db.execute('INSERT INTO alerts(created_at,severity,title,message) VALUES (?,?,?,?)', (now(),severity,title,message))


def open_alerts(path):
    with connect(path) as db: return db.execute('SELECT * FROM alerts WHERE acknowledged=0 ORDER BY created_at DESC').fetchall()


def acknowledge_alert(path, alert_id):
    with connect(path) as db: db.execute('UPDATE alerts SET acknowledged=1 WHERE id=?', (alert_id,))


def login_failures(path, key, since):
    with connect(path) as db: return db.execute('SELECT COUNT(*) FROM login_attempts WHERE client_key=? AND success=0 AND attempted_at>=?', (key,since)).fetchone()[0]


def record_login_attempt(path, key, success, attempted_at):
    with connect(path) as db: db.execute('INSERT INTO login_attempts(client_key,success,attempted_at) VALUES (?,?,?)', (key,int(success),attempted_at))


def dashboard_data(path):
    ts=latest_targets(path); ev=recent_events(path); al=open_alerts(path)
    return ts,ev,al,len(ts),sum(1 for t in ts if t['status']=='UP')

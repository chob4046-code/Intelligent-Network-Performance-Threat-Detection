import os
from flask import Flask
from .config import Config
from .db import init_db
from .routes import bp
from .monitor import start_monitor


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)
    init_db(app.config['DB_PATH'], app.config['ADMIN_USERNAME'], app.config['ADMIN_PASSWORD'])
    app.register_blueprint(bp)
    if not app.config.get('TESTING'):
        start_monitor(app.config)
    return app

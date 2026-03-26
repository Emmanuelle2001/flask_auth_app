import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from flask_security import Security, SQLAlchemyUserDatastore
from werkzeug.security import generate_password_hash
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from .models import User, Role
user_datastore = SQLAlchemyUserDatastore(db, User, Role)

def setup_logging(app):
    """Configura el sistema de logging de la aplicación."""
    if not os.path.exists('logs'):
        os.makedirs('logs')

    # Handler para archivo con rotación (máximo 1MB, guarda 5 archivos)
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=1_000_000,
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO)

    # Formato del log: fecha/hora | nivel | mensaje
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)

    # También mostrar logs en consola
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    app.logger.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)


def create_app():
    app = Flask(__name__)

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:2704@localhost/flasksecurity'

    app.config['SECURITY_PASSWORD_HASH'] = 'pbkdf2_sha512'
    app.config['SECURITY_PASSWORD_SALT'] = 'thisissecretsalt'

    Security(app, user_datastore)

    db.init_app(app)

    # Configurar logging
    setup_logging(app)

    with app.app_context():

        db.create_all()

        user_datastore.find_or_create_role(name='admin', description='Administrator')
        user_datastore.find_or_create_role(name='end-user', description='End User')

        encrypted_password = generate_password_hash('password', method='pbkdf2:sha256')

        from uuid import uuid4

        if not user_datastore.find_user(email='juan@example.com'):
            user_datastore.create_user(
                name='Juan',
                email='juan@example.com',
                password=encrypted_password,
                fs_uniquifier=str(uuid4())
            )

        if not user_datastore.find_user(email='admin@example.com'):
            user_datastore.create_user(
                name='Ismael',
                email='admin@example.com',
                password=encrypted_password,
                fs_uniquifier=str(uuid4())
            )

        db.session.commit()

        user_datastore.add_role_to_user(
            user_datastore.find_user(email='juan@example.com'),
            'end-user'
        )

        user_datastore.add_role_to_user(
            user_datastore.find_user(email='admin@example.com'),
            'admin'
        )

        db.session.commit()

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # LOG: Inicio de la aplicación
    app.logger.info('=== Aplicación iniciada correctamente ===')

    return app
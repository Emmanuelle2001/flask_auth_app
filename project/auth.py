from flask import Blueprint, render_template, redirect, url_for, request, flash, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from flask_security import login_required
from flask_security.utils import login_user, logout_user

from .models import User
from . import db, user_datastore

auth = Blueprint('auth', __name__, url_prefix='/security')


@auth.route('/login')
def login():
    return render_template('security/login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    try:
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            # LOG: Intento de acceso fallido
            current_app.logger.warning(
                f'LOGIN FALLIDO | correo={email} | ip={request.remote_addr}'
            )
            flash('El correo o la contraseña son incorrectos')
            return redirect(url_for('auth.login'))

        login_user(user, remember=remember)

        # LOG: Acceso exitoso de usuario
        current_app.logger.info(
            f'LOGIN EXITOSO | id={user.id} | correo={user.email} | ip={request.remote_addr}'
        )

        return redirect(url_for('main.profile'))

    except Exception as e:
        # LOG: Error inesperado en login
        current_app.logger.error(
            f'ERROR en login_post | correo={email} | error={str(e)}'
        )
        flash('Ocurrió un error inesperado. Intenta de nuevo.')
        return redirect(url_for('auth.login'))


@auth.route('/register')
def register():
    return render_template('security/register.html')


@auth.route('/register', methods=['POST'])
def register_post():
    from uuid import uuid4

    email = request.form.get('email')
    password = request.form.get('password')
    name = request.form.get('name')

    try:
        user = User.query.filter_by(email=email).first()

        if user:
            current_app.logger.warning(
                f'REGISTRO FALLIDO (correo duplicado) | correo={email} | ip={request.remote_addr}'
            )
            flash('Ese correo electronico ya existe')
            return redirect(url_for('auth.register'))

        new_user = user_datastore.create_user(
            name=name,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            fs_uniquifier=str(uuid4())
        )

        db.session.commit()

        # LOG: Registro exitoso de nuevo usuario
        current_app.logger.info(
            f'REGISTRO EXITOSO | id={new_user.id} | correo={email} | nombre={name} | ip={request.remote_addr}'
        )

        return redirect(url_for('auth.login'))

    except Exception as e:
        db.session.rollback()
        # LOG: Error en registro
        current_app.logger.error(
            f'ERROR en register_post | correo={email} | error={str(e)}'
        )
        flash('Ocurrió un error al registrar el usuario.')
        return redirect(url_for('auth.register'))


@auth.route('/logout')
@login_required
def logout():
    from flask_security import current_user
    # LOG: Cierre de sesión
    current_app.logger.info(
        f'LOGOUT | id={current_user.id} | correo={current_user.email} | ip={request.remote_addr}'
    )
    logout_user()
    return redirect(url_for('main.index'))
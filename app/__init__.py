import sys

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_principal import Principal
#Importing functions and variables to store user role
from .permissions import admin_permission, moderator_permission, user_permission, register_identity_permissions
import logging
from config import fernet
from logging.handlers import RotatingFileHandler


db = SQLAlchemy()
csrf = CSRFProtect()
bcrypt = Bcrypt()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
talisman = Talisman()
principal = Principal()




'''
Basic Config sets the root logger, which is used when running the program
Setting the filename inside the root logger means the URL to run is sent to the log file
Setting filename outside the root logger so URL is still sent to the terminal (default)
'''
#Setting up logging
logging.basicConfig(
    level=logging.INFO,
    format = '%(asctime)s - %(levelname)s - %(message)s',
    #filename='access.log',
    #filemode='a'
)
logger = logging.getLogger(__name__)

#Setting outside root so link still given to terminal
logger.addHandler(logging.FileHandler('app/log/access.logs', mode='a'))
#Log Rotation. Set to 1MB per log file with 5 backups
handler = RotatingFileHandler('app/log/access.log', maxBytes=1*1024*1024, backupCount=5)
logger.addHandler(handler)


@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))     #Primary key set as type in models.py

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)


    #Custom CSP
    csp = {
        'default-src': ["'self'"],
        'script-src': ["'self'",
                        "https://cdn.jsdelivr.net"], #Allows JS from jsDelivr
        'style-src': ["'self'",
                      "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css",
                      "https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css"],
        'font-src': ["'self'",
                     "https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css",
                      "https://cdn.jsdelivr.net/npm/sweetalert2@11/dist/sweetalert2.min.css"]
    }

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    limiter.init_app(app)
    talisman.init_app(app, content_security_policy=csp)
    principal.init_app(app)
    #Session(app)

    register_identity_permissions(app) #Defined in permissions.py

    from .routes import main
    app.register_blueprint(main)

    with app.app_context():
        from .models import User
        db.drop_all()
        db.create_all()

        # Hashing passwords:
        adminpass = bcrypt.generate_password_hash('Adminpass!23').decode('utf-8')
        modpass = bcrypt.generate_password_hash('Modpass!23').decode('utf-8')
        userpass = bcrypt.generate_password_hash('Userpass!23').decode('utf-8')


        #Encrypting bio field:
        #Fernet requires bytes not strings so encoding the data
        adminbioencrypt = fernet.encrypt("I'm an administrator".encode())
        modbioencrypt = fernet.encrypt("I'm a moderator".encode())
        userbioencrypt = fernet.encrypt("I'm a basic user".encode())

        users = [
            {"username": "user1@email.com", "password": userpass, "role": "user", "bio": userbioencrypt,
                        "Log in Attempts": 0},
            {"username": "mod1@email.com", "password": modpass, "role": "moderator", "bio": modbioencrypt,
                        "Log in Attempts": 0},
            {"username": "admin1@email.com", "password": adminpass, "role": "admin", "bio": adminbioencrypt,
                        "Log in Attempts": 0},
        ]



        for user in users:
            user = User(username=user["username"], password=user["password"], role=user["role"], bio=user["bio"],
                        loginattempts=user["Log in Attempts"])
            db.session.add(user)
            db.session.commit()







    return app


from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman


db = SQLAlchemy()
csrf = CSRFProtect()
bcrypt = Bcrypt()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")
talisman = Talisman()




@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))     #Primary key set as type in models.py

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    limiter.init_app(app)
    talisman.init_app(app)
    #Session(app)


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



        users = [
            {"username": "user1@email.com", "password": userpass, "role": "user", "bio": "I'm a basic user",
                        "Log in Attempts": 0},
            {"username": "mod1@email.com", "password": modpass, "role": "moderator", "bio": "I'm a moderator",
                        "Log in Attempts": 0},
            {"username": "admin1@email.com", "password": adminpass, "role": "admin", "bio": "I'm an administrator",
                        "Log in Attempts": 0},
        ]



        for user in users:
            user = User(username=user["username"], password=user["password"], role=user["role"], bio=user["bio"],
                        loginattempts=user["Log in Attempts"])
            db.session.add(user)
            db.session.commit()

    return app


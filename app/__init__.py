from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
csrf = CSRFProtect()

bcrypt = Bcrypt()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    csrf.init_app(app)


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
            {"username": "user1@email.com", "password": userpass, "role": "user", "bio": "I'm a basic user"},
            {"username": "mod1@email.com", "password": modpass, "role": "moderator", "bio": "I'm a moderator"},
            {"username": "admin1@email.com", "password": adminpass, "role": "admin", "bio": "I'm an administrator"}
        ]



        for user in users:
            user = User(username=user["username"], password=user["password"], role=user["role"], bio=user["bio"])
            db.session.add(user)
            db.session.commit()

    return app


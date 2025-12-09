from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv



#Getting secret key from app level (environmental variable)
load_dotenv()
#Key is stored as String in .env, converting into bytes (expected for fernet objects)
key = os.environ.get('FLASK_SECRET_KEY').encode()
fernet= Fernet(key)

dbURL = os.environ.get('DATABASE_URL')





class Config:
    DEBUG = True
    SECRET_KEY = key #Has to be string so set to key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    TESTING = True


class prodConfig():
    DEBUG = False
    SECRET_KEY = key
    SQLALCHEMY_DATABASE_URI = dbURL
    WTF_CSRF_ENABLED = True




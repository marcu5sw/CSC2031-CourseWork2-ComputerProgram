from cryptography.fernet import Fernet



'''
Note fernet is generating a new key each time the server is run
Works because Database is reset each time the server restarts
Other option is to set it at OS level but might not have anything set when submitting
'''

#Generating a new key using Fernet class
key = Fernet.generate_key()
fernet = Fernet(key) #initializing to be used for encryption and decryption





class Config:
    DEBUG = True
    SECRET_KEY = key #Has to be string so set to key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True


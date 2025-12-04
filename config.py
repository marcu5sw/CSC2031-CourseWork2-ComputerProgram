from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv



#Getting secret key from OS level (environmental variable)
'''key = os.environ.get('SECRET_KEY')

#print (key)

#If there isn't an environmental variable called SECRET_KEY, Fernet to create one
if key is None:
    key = Fernet.generate_key()

#Can't encode None so can't declair above
else:
    key = key.encode()


#print (key)


fernet = Fernet(key) #Initializing to be used elsewhere'''


load_dotenv()
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
print(SECRET_KEY)



class Config:
    DEBUG = True
    SECRET_KEY = SECRET_KEY #Has to be string so set to key
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True


#print(Config.SECRET_KEY)



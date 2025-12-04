from app import create_app
from cryptography.fernet import Fernet
import os
from config import fernet


#key = Fernet.generate_key()


app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
    #print(key)
    #print(fernet)





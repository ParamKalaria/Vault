import os
import sys
from cryptography.fernet import Fernet

key_name  = sys.argv[1]
file_name = sys.argv[2]

def encrypt():
    try:
        print("doing")
        with open(key_name,'rb') as file_key:
            key = file_key.read()     
        
        fernet = Fernet(key)
    
        with open(file_name,'rb') as simple_text:
            real_text = simple_text.read()
        text_encrypt = fernet.encrypt(real_text)  
    
        with open (file_name,'wb') as encrypted_text:
            encrypted_text.write(text_encrypt)
    
        file_key.close()
        simple_text.close()
        encrypted_text.close()
    except:
        print()

encrypt()
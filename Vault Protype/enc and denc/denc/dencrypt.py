from cryptography.fernet import Fernet
import sys


key_name  = sys.argv[1]
file_name = sys.argv[2]

def dencrypt():
    
    with open(key_name,'rb') as file_key:
        key = file_key.read()
    
    fernet = Fernet(key)
    
    
    with open(file_name,'rb') as encrypted_file:
        encrypted_text = encrypted_file.read()
    
    
    decrypted_text = fernet.decrypt(encrypted_text)
    
    
    with open(file_name,'wb') as decrypted_file:
        decrypted_file.write(decrypted_text)
    
    
    file_key.close()
    encrypted_file.close()
    decrypted_file.close()

dencrypt()
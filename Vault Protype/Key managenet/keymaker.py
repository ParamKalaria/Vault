import os
from cryptography.fernet import Fernet
import sys

key_name=sys.argv[1]
def keymaker():
    
   key = Fernet.generate_key()
   key_file=open(f'{key_name}.key','wb')
   key_file.write(key)
   key_file.close   

keymaker()
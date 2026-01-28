import sys as s
import os
from cryptography.fernet import Fernet
import threading

def login():
    username = s.argv[1]
    password = input('Enter Password=')
    if(username=="admin"):
        if(password=="admin"):
            os.system('clear')
            info()
            task_select()
        else:
            print("password error")
    else:
        print("username error")

def info():
    print('[+] ParaVault by Param Kalaria')
    print("\n")
    print("1.Encrypt")
    print("2.Dencrypt")
    print("3.Change Master Password")
    print("4.Key Management")
    print("5.Help")
    print("6.Logout")
    print("7.clear")

def task_select():

    print("\n")
    a=input('Enter Input=>')

    if(a=="Encrypt" or a=='1'):
        print('[+] Add File with Extensions')
        AES_process.encrypt()
        os.system('clear')
        info()
        task_select()
    
    elif(a=="Dencrypt" or a=='2'):
        print('[+] Add File with Extensions')
        AES_process.dencrypt()
        os.system('clear')
        info()
        task_select()
    
    elif(a=="Change Master Password" or a=='3'):
        Master_Password()
        os.system('clear')
        info()
        task_select()
    
    elif(a=="Key Management" or a=='4'):
        key_management()
        os.system('clear')
        info()
        task_select()
    
    elif(a=="Help" or a=='5'):
        os.system('clear')
        info()
        task_select()
    
    elif(a=="Logout" or a=='6'):
        os.system('clear')
        os.system('exit')
    
    elif(a=="clear" or a=='7'):
        os.system('clear')
        task_select()
    
    else:
        print('Input Error')
        os.system('clear')
        info()
        task_select()
    
    


    
def Master_Password():
    print("\n")
    print('master password')
    task_select()

def key_management():
    print("\n")

    print("1.create")
    #print("2.keym")

    a=input('Enter Input=>')

    if(a=="create" or a=='1'):
        keys.create()    
    elif(a=="keym" or a=='2'):
        keys.keym()
    
    os.system('clear')
    info()
    task_select()

def list_files():
    files = os.listdir()
    for file in files:
        if os.path.isfile(file):
            print(file)

class AES_process:

    def file_check(files_to_check):
        print("File Checking...")
        filecheck= os.path.isfile(files_to_check)
        return filecheck


    def encrypt():
        print("\n")  
        mainfile=input('select file to encrypt:') 
        key=input('select key to encrypt the files:')
        fi=AES_process.file_check(key)
        
        if(fi==True):
            print("encrypting...")
            try: 
                with open(key,'rb') as file_key:
                    key = file_key.read()     
        
                fernet = Fernet(key)

                with open(mainfile,'rb') as simple_text:
                    real_text = simple_text.read()
                text_encrypt = fernet.encrypt(real_text)  
    
                with open (mainfile,'wb') as encrypted_text:
                    encrypted_text.write(text_encrypt)
    
                file_key.close()
                simple_text.close()
                encrypted_text.close()
            except:
                print("Error while encrypting") 
            print("Task in complete") 
        else:
            print("File Not Found!")    
            print("Task in incomplete")  
        #t.sleep(2000)
               

    def dencrypt():
        print("\n")
        mainfile=input('select file to dencrypt:')
        key=input('select key to dencrypt the files:')
        fi=AES_process.file_check(key)
        
        if(fi==True):
            print("dencrypting...")

            try:
                with open(key,'rb') as file_key:
                    key = file_key.read()    
                
                fernet = Fernet(key)

                with open(mainfile,'rb') as encrypted_file:
                    encrypted_text = encrypted_file.read()
    
    
                decrypted_text = fernet.decrypt(encrypted_text)
    
    
                with open(mainfile,'wb') as decrypted_file:
                    decrypted_file.write(decrypted_text)
    
    
                file_key.close()
                encrypted_file.close()
                decrypted_file.close()  
            except:
                print("Error while dencrypting")  
            print("Task in complete")   
        else:
            print("File Not Found!")
            print("Task in incomplete") 
        #t.sleep(2000)

class keys:
    
    def create():
        key_name=input("Enter Key Name:")
        key = Fernet.generate_key()
        key_file=open(f'{key_name}.key','wb')
        key_file.write(key)
        key_file.close
        #t.sleep(2000)

    def keym():
        print('keym')

login()

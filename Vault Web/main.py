from zipfile import ZipFile
from flask import Flask, render_template ,request,session,send_from_directory,redirect,send_file,after_this_request
from cryptography.fernet import Fernet
import os
import string
import random
import socket
import requests as req
import uuid
import shutil


app = Flask(__name__, template_folder='templates',static_url_path='/static')
#app.secret_key = 'vault1'
app.config['SECRET_KEY'] = ']#3;t/t*x6NEEYU%'
app.config['SESSION_TYPE'] = 'filesystem'

ran = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))



class AES_process:

    def file_check(files_to_check):
        filecheck= os.path.isfile(files_to_check)
        return filecheck


    def encrypt(mainfile,key):
        try: 
            with open(key,'rb') as file_key:
                key = file_key.read()
    
            fernet = Fernet(key)

            with open(mainfile,'rb') as simple_text:
                real_text = simple_text.read()
            text_encrypt = fernet.encrypt(real_text)  

            with open(mainfile,'wb') as encrypted_text:
                encrypted_text.write(text_encrypt)

            file_key.close()
            simple_text.close()
            encrypted_text.close()
        except Exception as e:
            return e

               

    def dencrypt(mainfile,key):
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
        except Exception as e:
            return e

class keys:    
    def create(key_name):
        sid=session.get('id')
        key = Fernet.generate_key()
        key_file=open('uploads/'+sid+"/"+key_name+'.key','wb')
        key_file.write(key)
        key_file.close()





#Main Flask Worker
@app.route('/', methods = ['GET'])
def login():
    
    if request.method == 'GET':
        session['id']=ran
        return render_template("main.html",content=session.get('id'))
    else:
        return err()
    




@app.before_request
def ensure_unique_session_id():
    if 'id' not in session:
        session['id'] = str(uuid.uuid4())

    
  

# Encrypt route
@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    sid = session['id']
    path = os.path.join('uploads', sid)
    os.makedirs(path, exist_ok=True)

    try:
        uploaded_file = request.files['file']
        file_path = os.path.join(path, uploaded_file.filename)
        key_path = file_path + '.key'
        zip_path = os.path.join(path, 'Encrypted.zip')

        # Save original file
        uploaded_file.save(file_path)

        # Generate key and save
        key = Fernet.generate_key()
        with open(key_path, 'wb') as kf:
            kf.write(key)

        # Encrypt file
        fernet = Fernet(key)
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(file_path, 'wb') as f:
            f.write(encrypted)

        # Create ZIP
        with ZipFile(zip_path, 'w') as zipf:
            zipf.write(file_path, arcname=uploaded_file.filename)
            zipf.write(key_path, arcname=os.path.basename(key_path))
  

        return send_file(zip_path, as_attachment=True)

    except Exception as e:
        return str(e)
    
    finally:
        session.clear()
        return redirect('/')
        #shutil.rmtree(path)


   



    
# Decrypt route
@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    sid = session['id']
    path = os.path.join('uploads', sid)
    os.makedirs(path, exist_ok=True)

    try:
        enc_file = request.files['mainfile']
        key_file = request.files['keyfile']
        enc_path = os.path.join(path, enc_file.filename)
        key_path = os.path.join(path, key_file.filename)
        zip_path = os.path.join(path, 'Decrypted.zip')

        enc_file.save(enc_path)
        key_file.save(key_path)

        # Load key and decrypt
        with open(key_path, 'rb') as kf:
            key = kf.read()
        fernet = Fernet(key)
        with open(enc_path, 'rb') as ef:
            encrypted = ef.read()
        decrypted = fernet.decrypt(encrypted)
        with open(enc_path, 'wb') as df:
            df.write(decrypted)

        # Create ZIP
        with ZipFile(zip_path, 'w') as zipf:
            zipf.write(enc_path, arcname=enc_file.filename)

        return send_file(zip_path, as_attachment=True)

    except Exception as e:
        return str(e)
    
    finally:
        session.clear()
        return redirect('/')
        #shutil.rmtree(path)


    





def err():
    return 'ERROR!!! Something went wrong! your session is closed and files is removed from storage.'





if __name__ == '__main__':
    #ssl_certi=('certi/fullchain.pem','certi/privkey.pem')
    if os.path.exists('uploads'):       
        app.run(host='0.0.0.0',port=8000,debug=True)
    else:        
        os.mkdir('uploads')
from zipfile import ZipFile
from flask import Flask, render_template, request, session, redirect, send_file
from cryptography.fernet import Fernet
import os
import uuid
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates', static_url_path='/static')
app.config['SECRET_KEY'] = ']#3;t/t*x6NEEYU%'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for file I/O
UPLOAD_DIR = 'uploads'

# Ensure uploads directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)


class CryptoHandler:
    """Handles encryption and decryption operations efficiently."""
    
    @staticmethod
    def encrypt_file(file_path, key):
        """Encrypt file using provided key."""
        try:
            with open(key, 'rb') as kf:
                key_data = kf.read()
            
            fernet = Fernet(key_data)
            
            # Read and encrypt in chunks for large files
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted = fernet.encrypt(data)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted)
                
            return True
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_file(file_path, key):
        """Decrypt file using provided key."""
        try:
            with open(key, 'rb') as kf:
                key_data = kf.read()
            
            fernet = Fernet(key_data)
            
            with open(file_path, 'rb') as f:
                encrypted = f.read()
            
            decrypted = fernet.decrypt(encrypted)
            
            with open(file_path, 'wb') as f:
                f.write(decrypted)
                
            return True
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise


class KeyManager:
    """Manages encryption key operations."""
    
    @staticmethod
    def create_key(key_name):
        """Generate and save a new encryption key."""
        try:
            sid = session.get('id')
            if not sid:
                return False
            
            session_dir = os.path.join(UPLOAD_DIR, sid)
            os.makedirs(session_dir, exist_ok=True)
            
            key = Fernet.generate_key()
            key_path = os.path.join(session_dir, f"{key_name}.key")
            
            with open(key_path, 'wb') as kf:
                kf.write(key)
            
            return True
        except Exception as e:
            logger.error(f"Key creation error: {str(e)}")
            return False





@app.before_request
def ensure_unique_session_id():
    """Ensure each session has a unique ID."""
    if 'id' not in session:
        session['id'] = str(uuid.uuid4())


@app.route('/', methods=['GET'])
def index():
    """Display the main dashboard."""
    return render_template("main.html", content=session.get('id'))


@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    """Encrypt uploaded file and return as ZIP."""
    sid = session.get('id')
    session_path = os.path.join(UPLOAD_DIR, sid)
    os.makedirs(session_path, exist_ok=True)

    try:
        uploaded_file = request.files.get('file')
        if not uploaded_file or uploaded_file.filename == '':
            return 'Error: No file selected', 400

        file_path = os.path.join(session_path, uploaded_file.filename)
        key_path = f"{file_path}.key"
        zip_path = os.path.join(session_path, 'Encrypted.zip')

        # Save original file
        uploaded_file.save(file_path)

        # Generate and save key
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

        response = send_file(zip_path, as_attachment=True, download_name='Encrypted.zip')
        
        # Clean up after sending
        @response.call_on_close
        def cleanup():
            try:
                os.remove(file_path)
                os.remove(key_path)
                os.remove(zip_path)
            except:
                pass
        
        return response

    except Exception as e:
        logger.error(f"Encryption route error: {str(e)}")
        return f'Error: {str(e)}', 500


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    """Decrypt uploaded files and return as ZIP."""
    sid = session.get('id')
    session_path = os.path.join(UPLOAD_DIR, sid)
    os.makedirs(session_path, exist_ok=True)

    try:
        enc_file = request.files.get('mainfile')
        key_file = request.files.get('keyfile')
        
        if not enc_file or not key_file:
            return 'Error: Both encrypted file and key file are required', 400

        enc_path = os.path.join(session_path, enc_file.filename)
        key_path = os.path.join(session_path, key_file.filename)
        zip_path = os.path.join(session_path, 'Decrypted.zip')

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
            zipf.write(enc_path, arcname=enc_file.filename.replace('.encrypted', ''))

        response = send_file(zip_path, as_attachment=True, download_name='Decrypted.zip')
        
        # Clean up after sending
        @response.call_on_close
        def cleanup():
            try:
                os.remove(enc_path)
                os.remove(key_path)
                os.remove(zip_path)
            except:
                pass
        
        return response

    except Exception as e:
        logger.error(f"Decryption route error: {str(e)}")
        return f'Error: {str(e)}', 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)  # debug=False in production
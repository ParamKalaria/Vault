from zipfile import ZipFile
from flask import Flask, render_template, request, session, redirect, send_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import uuid
import logging
import secrets
import hashlib

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
    """Handles AES-256-GCM encryption and decryption operations."""
    
    # Encryption constants
    KEY_SIZE = 32  # 256-bit key
    NONCE_SIZE = 12  # 96-bit nonce (standard for GCM)
    TAG_SIZE = 16  # 128-bit authentication tag
    SALT_SIZE = 16  # 128-bit salt
    
    @staticmethod
    def _derive_key(password, salt):
        """Derive encryption key from password using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=CryptoHandler.KEY_SIZE,
            salt=salt,
            info=b'vault-encryption',
            backend=default_backend()
        )
        return hkdf.derive(password)
    
    @staticmethod
    def encrypt_file(file_path, key_file_path):
        """Encrypt file using AES-256-GCM with provided key file."""
        try:
            # Read the password/key from key file
            with open(key_file_path, 'rb') as kf:
                password = kf.read()
            
            # Generate random salt and nonce
            salt = secrets.token_bytes(CryptoHandler.SALT_SIZE)
            nonce = secrets.token_bytes(CryptoHandler.NONCE_SIZE)
            
            # Derive encryption key from password
            key = CryptoHandler._derive_key(password, salt)
            
            # Read plaintext
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Encrypt using AES-256-GCM
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Write encrypted file: salt + nonce + tag + ciphertext
            with open(file_path, 'wb') as f:
                f.write(salt)
                f.write(nonce)
                f.write(encryptor.tag)
                f.write(ciphertext)
            
            logger.info(f"✓ File encrypted successfully: {os.path.basename(file_path)}")
            return True
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_file(file_path, key_file_path):
        """Decrypt file using AES-256-GCM with provided key file."""
        try:
            # Read the password/key from key file
            with open(key_file_path, 'rb') as kf:
                password = kf.read()
            
            # Read encrypted file: salt + nonce + tag + ciphertext
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Extract components
            salt = encrypted_data[:CryptoHandler.SALT_SIZE]
            nonce = encrypted_data[CryptoHandler.SALT_SIZE:CryptoHandler.SALT_SIZE + CryptoHandler.NONCE_SIZE]
            tag = encrypted_data[CryptoHandler.SALT_SIZE + CryptoHandler.NONCE_SIZE:
                                CryptoHandler.SALT_SIZE + CryptoHandler.NONCE_SIZE + CryptoHandler.TAG_SIZE]
            ciphertext = encrypted_data[CryptoHandler.SALT_SIZE + CryptoHandler.NONCE_SIZE + CryptoHandler.TAG_SIZE:]
            
            # Derive decryption key from password
            key = CryptoHandler._derive_key(password, salt)
            
            # Decrypt using AES-256-GCM
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Write decrypted file
            with open(file_path, 'wb') as f:
                f.write(plaintext)
            
            logger.info(f"✓ File decrypted successfully: {os.path.basename(file_path)}")
            return True
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise


class KeyManager:
    """Manages encryption key generation and management."""
    
    @staticmethod
    def create_key(key_name):
        """Generate and save a new random encryption key."""
        try:
            sid = session.get('id')
            if not sid:
                return False
            
            session_dir = os.path.join(UPLOAD_DIR, sid)
            os.makedirs(session_dir, exist_ok=True)
            
            # Generate 32-byte (256-bit) random key
            key = secrets.token_bytes(32)
            key_path = os.path.join(session_dir, f"{key_name}.key")
            
            with open(key_path, 'wb') as kf:
                kf.write(key)
            
            logger.info(f"✓ New encryption key created: {key_name}.key")
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

    file_path = None
    key_path = None
    zip_path = None

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
        key = secrets.token_bytes(32)
        with open(key_path, 'wb') as kf:
            kf.write(key)

        # Encrypt file using AES-256-GCM
        CryptoHandler.encrypt_file(file_path, key_path)

        # Create ZIP
        with ZipFile(zip_path, 'w') as zipf:
            zipf.write(file_path, arcname=uploaded_file.filename)
            zipf.write(key_path, arcname=os.path.basename(key_path))

        response = send_file(zip_path, as_attachment=True, download_name='Encrypted.zip')
        
        # Clean up after sending
        @response.call_on_close
        def cleanup():
            try:
                # Delete files with delay to ensure download completes
                import time
                time.sleep(1)
                
                if file_path and os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"✓ Deleted: {file_path}")
                    
                if key_path and os.path.exists(key_path):
                    os.remove(key_path)
                    logger.info(f"✓ Deleted: {key_path}")
                    
                if zip_path and os.path.exists(zip_path):
                    os.remove(zip_path)
                    logger.info(f"✓ Deleted: {zip_path}")
                    
                # Remove session directory if empty
                try:
                    if os.path.exists(session_path) and not os.listdir(session_path):
                        os.rmdir(session_path)
                        logger.info(f"✓ Removed empty session directory: {session_path}")
                except OSError as e:
                    logger.debug(f"Session directory not empty or error: {str(e)}")
                    
            except Exception as e:
                logger.error(f"Cleanup error: {str(e)}")
        
        return response

    except Exception as e:
        logger.error(f"Encryption route error: {str(e)}")
        # Clean up on error
        try:
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
            if key_path and os.path.exists(key_path):
                os.remove(key_path)
            if zip_path and os.path.exists(zip_path):
                os.remove(zip_path)
        except:
            pass
        return f'Error: {str(e)}', 500


@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    """Decrypt uploaded file and return original file directly."""
    sid = session.get('id')
    session_path = os.path.join(UPLOAD_DIR, sid)
    os.makedirs(session_path, exist_ok=True)

    enc_path = None
    key_path = None

    try:
        enc_file = request.files.get('mainfile')
        key_file = request.files.get('keyfile')
        
        if not enc_file or not key_file:
            return 'Error: Both encrypted file and key file are required', 400

        enc_path = os.path.join(session_path, enc_file.filename)
        key_path = os.path.join(session_path, key_file.filename)

        enc_file.save(enc_path)
        key_file.save(key_path)

        # Decrypt file using AES-256-GCM
        CryptoHandler.decrypt_file(enc_path, key_path)

        # Send decrypted file directly (remove .encrypted extension if present)
        download_name = enc_file.filename
        if download_name.endswith('.encrypted'):
            download_name = download_name[:-10]  # Remove '.encrypted'

        response = send_file(enc_path, as_attachment=True, download_name=download_name)
        
        # Clean up after sending
        @response.call_on_close
        def cleanup():
            try:
                # Delete files with delay to ensure download completes
                import time
                time.sleep(1)
                
                if enc_path and os.path.exists(enc_path):
                    os.remove(enc_path)
                    logger.info(f"✓ Deleted: {enc_path}")
                    
                if key_path and os.path.exists(key_path):
                    os.remove(key_path)
                    logger.info(f"✓ Deleted: {key_path}")
                    
                # Remove session directory if empty
                try:
                    if os.path.exists(session_path) and not os.listdir(session_path):
                        os.rmdir(session_path)
                        logger.info(f"✓ Removed empty session directory: {session_path}")
                except OSError as e:
                    logger.debug(f"Session directory not empty or error: {str(e)}")
                    
            except Exception as e:
                logger.error(f"Cleanup error: {str(e)}")
        
        return response

    except Exception as e:
        logger.error(f"Decryption route error: {str(e)}")
        # Clean up on error
        try:
            if enc_path and os.path.exists(enc_path):
                os.remove(enc_path)
            if key_path and os.path.exists(key_path):
                os.remove(key_path)
        except:
            pass
        return f'Error: {str(e)}', 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)  # debug=False in production
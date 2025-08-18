from flask import Flask, request, jsonify, send_from_directory
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
import os
import asyncio
import uuid
import json
import time
import hashlib
import logging
from cryptography.fernet import Fernet
from security import (
    rate_limit, validate_phone_number, validate_file_upload, 
    sanitize_input, log_security_event
)

# API credentials
api_id = 21238942
api_hash = "c9d04653ba38ac4c8e226b0913cbe9f9"

# Generate encryption key
SECRET_KEY = Fernet.generate_key()
cipher = Fernet(SECRET_KEY)

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
SESSIONS_FOLDER = 'sessions'
FOLDERS_FILE = 'user_folders.json'
SESSION_TIMEOUT = 3600  # 1 hour

# Create directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SESSIONS_FOLDER, exist_ok=True)

# Session management
session_timestamps = {}
phone_code_hashes = {}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_session_path(phone):
    """Get encrypted session file path"""
    phone_hash = hashlib.sha256(phone.encode()).hexdigest()
    return os.path.join(SESSIONS_FOLDER, f"{phone_hash}.session")



def cleanup_expired_sessions():
    """Clean up expired sessions"""
    current_time = time.time()
    expired_phones = []
    
    for phone, timestamp in session_timestamps.items():
        if current_time - timestamp > SESSION_TIMEOUT:
            expired_phones.append(phone)
    
    for phone in expired_phones:
        session_path = get_session_path(phone)
        if os.path.exists(session_path):
            os.remove(session_path)
        del session_timestamps[phone]
        if phone in phone_code_hashes:
            del phone_code_hashes[phone]
        logger.info(f"Cleaned up expired session for {phone}")

def load_user_folders():
    if os.path.exists(FOLDERS_FILE):
        try:
            with open(FOLDERS_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error("Error reading user folders file")
    return {}

def save_user_folders(folders_data):
    try:
        with open(FOLDERS_FILE, 'w') as f:
            json.dump(folders_data, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving user folders: {e}")

@app.route('/')
def index():
    return send_from_directory('.', 'consent.html')

@app.route('/privacy-policy')
def privacy_policy():
    return send_from_directory('.', 'privacy_policy.html')

@app.route('/login')
def login():
    return send_from_directory('.', 'login.html')



@app.route('/upload-page')
def upload_page():
    return send_from_directory('.', 'upload.html')

@app.route('/send_code', methods=['POST'])
@rate_limit
def send_code():
    """Send OTP to phone number"""
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        
        # Validate phone number
        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            log_security_event("INVALID_PHONE", f"Invalid phone format: {phone}")
            return jsonify({"status": "error", "message": result}), 400
        
        phone = result
        session_path = get_session_path(phone)
        
        # Clean up expired sessions
        cleanup_expired_sessions()
        
        async def main():
            try:
                client = TelegramClient(session_path, api_id, api_hash)
                await client.connect()
                result = await client.send_code_request(phone)
                phone_code_hashes[phone] = result.phone_code_hash
                session_timestamps[phone] = time.time()
                await client.disconnect()
                
                log_security_event("OTP_SENT", f"OTP sent to {phone}", phone)
                return {"status": "code_sent", "message": f"OTP sent to {phone}. Check your Telegram app for the code."}
            except Exception as e:
                logger.error(f"SEND CODE ERROR: {e}")
                log_security_event("OTP_ERROR", str(e), phone)
                return {"status": "error", "message": "Failed to send OTP"}

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(main())
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Unexpected error in send_code: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/verify_code', methods=['POST'])
@rate_limit
def verify_code():
    """Verify OTP code"""
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        code = data.get('code') if data else None
        
        # Validate inputs
        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            return jsonify({"status": "error", "message": result}), 400
        
        phone = result
        code = sanitize_input(code)
        
        if not code:
            return jsonify({"status": "error", "message": "OTP code is required"}), 400
        
        session_path = get_session_path(phone)
        
        async def main():
            try:
                client = TelegramClient(session_path, api_id, api_hash)
                await client.connect()

                phone_code_hash = phone_code_hashes.get(phone)
                if not phone_code_hash:
                    raise Exception("No phone_code_hash found. Request OTP again.")

                await client.sign_in(phone=phone, code=code, phone_code_hash=phone_code_hash)
                session_timestamps[phone] = time.time()
                await client.disconnect()
                
                log_security_event("LOGIN_SUCCESS", f"User logged in successfully", phone)
                return {"status": "success"}
            except SessionPasswordNeededError:
                log_security_event("2FA_REQUIRED", f"2FA required for {phone}", phone)
                return {"status": "2fa_required"}
            except Exception as e:
                logger.error(f"VERIFY CODE ERROR: {e}")
                log_security_event("LOGIN_FAILED", str(e), phone)
                return {"status": "failed", "error": "Invalid OTP or session expired"}

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(main())
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Unexpected error in verify_code: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/verify_password', methods=['POST'])
@rate_limit
def verify_password():
    """Verify 2FA password"""
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        password = data.get('password') if data else None
        
        # Validate inputs
        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            return jsonify({"status": "error", "message": result}), 400
        
        phone = result
        password = sanitize_input(password)
        
        if not password:
            return jsonify({"status": "error", "message": "Password is required"}), 400
        
        session_path = get_session_path(phone)
        
        async def main():
            try:
                client = TelegramClient(session_path, api_id, api_hash)
                await client.connect()
                if not await client.is_user_authorized():
                    await client.sign_in(password=password)
                session_timestamps[phone] = time.time()
                await client.disconnect()
                
                log_security_event("2FA_SUCCESS", f"2FA verification successful", phone)
                return {"status": "success"}
            except Exception as e:
                logger.error(f"VERIFY PASSWORD ERROR: {e}")
                log_security_event("2FA_FAILED", str(e), phone)
                return {"status": "failed", "error": "Invalid password"}

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(main())
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Unexpected error in verify_password: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/upload', methods=['POST'])
@rate_limit
def upload():
    """Upload files to Telegram"""
    try:
        phone = request.form.get('phone')
        folder_name = request.form.get('folderName')
        files = request.files.getlist('file')
        
        # Validate phone number
        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            return jsonify({"status": "error", "message": result}), 400
        
        phone = result
        folder_name = sanitize_input(folder_name)
        
        if not files:
            return jsonify({"status": "error", "message": "No files provided"}), 400
        
        session_path = get_session_path(phone)
        
        # Validate each file
        for file in files:
            is_valid, result = validate_file_upload(file)
            if not is_valid:
                return jsonify({"status": "error", "message": result}), 400
        
        async def main():
            client = TelegramClient(session_path, api_id, api_hash)
            await client.connect()
            
            uploaded_files = []
            for file in files:
                try:
                    filename = f"{uuid.uuid4().hex}_{file.filename}"
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)
                    
                    await client.send_file("me", file_path, caption=folder_name or "")
                    uploaded_files.append(file.filename)
                    
                    # Save folder to user folders if not already saved
                    if folder_name:
                        user_folders = load_user_folders()
                        if phone not in user_folders:
                            user_folders[phone] = []
                        if folder_name not in user_folders[phone]:
                            user_folders[phone].append(folder_name)
                            save_user_folders(user_folders)
                    
                    # Clean up temporary file
                    os.remove(file_path)
                    
                except Exception as e:
                    logger.error(f"Error uploading {file.filename}: {e}")
                    # Clean up on error
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    raise e
            
            session_timestamps[phone] = time.time()
            await client.disconnect()
            
            log_security_event("FILES_UPLOADED", f"Uploaded {len(uploaded_files)} files", phone)
            return {"status": "success", "files": uploaded_files}

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(main())
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"UPLOAD ERROR: {e}")
        return jsonify({"status": "error", "message": "Upload failed"}), 500

@app.route('/list_folders', methods=['POST'])
@rate_limit
def list_folders():
    """List all folders for the user"""
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        
        # Validate phone number
        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            return jsonify({"status": "error", "message": result}), 400
        
        phone = result
        
        # Only return folders created through the app
        user_folders = load_user_folders()
        user_folder_list = user_folders.get(phone, [])
        
        log_security_event("FOLDERS_LISTED", f"Listed {len(user_folder_list)} folders", phone)
        return jsonify({"status": "success", "folders": sorted(user_folder_list)})
        
    except Exception as e:
        logger.error(f"LIST FOLDERS ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to list folders"}), 500

@app.route('/create_folder', methods=['POST'])
@rate_limit
def create_folder():
    """Create a new folder for the user"""
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        folder_name = data.get('folder_name') if data else None
        
        # Validate inputs
        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            return jsonify({"status": "error", "message": result}), 400
        
        phone = result
        folder_name = sanitize_input(folder_name)
        
        if not folder_name or not folder_name.strip():
            return jsonify({"status": "error", "message": "Folder name is required"}), 400
        
        folder_name = folder_name.strip()
        user_folders = load_user_folders()
        
        if phone not in user_folders:
            user_folders[phone] = []
        
        if folder_name in user_folders[phone]:
            return jsonify({"status": "error", "message": "Folder already exists"}), 400
        
        user_folders[phone].append(folder_name)
        save_user_folders(user_folders)
        
        log_security_event("FOLDER_CREATED", f"Created folder: {folder_name}", phone)
        return jsonify({"status": "success", "folder": folder_name})
        
    except Exception as e:
        logger.error(f"CREATE FOLDER ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to create folder"}), 500

@app.route('/list_files_in_folder', methods=['POST'])
@rate_limit
def list_files_in_folder():
    """List all files in a specific folder"""
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        folder = data.get('folder') if data else None
        
        # Validate inputs
        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            return jsonify({"status": "error", "message": result}), 400
        
        phone = result
        folder = sanitize_input(folder)
        
        if not folder:
            return jsonify({"status": "error", "message": "Folder name is required"}), 400
        
        session_path = get_session_path(phone)
        
        async def main():
            try:
                client = TelegramClient(session_path, api_id, api_hash)
                await client.connect()
                
                # Get messages from Saved Messages
                messages = await client.get_messages("me", limit=200)
                files = []
                
                for msg in messages:
                    # Check if message has a file and the caption matches the folder
                    if msg.file and msg.text and msg.text.strip() == folder:
                        files.append({
                            "id": msg.id,
                            "name": msg.file.name,
                            "size": msg.file.size,
                            "mime_type": msg.file.mime_type,
                            "date": msg.date.isoformat()
                        })
                
                await client.disconnect()
                
                log_security_event("FILES_LISTED", f"Listed {len(files)} files in folder: {folder}", phone)
                return {"status": "success", "files": files}
                
            except Exception as e:
                logger.error(f"LIST FILES IN FOLDER ERROR: {e}")
                return {"status": "error", "message": str(e)}

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(main())
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"LIST FILES IN FOLDER ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to list files"}), 500

@app.route('/get_file/<phone>/<int:msg_id>')
def get_file(phone, msg_id):
    """Serve a file from Telegram Saved Messages"""
    try:
        session_path = get_session_path(phone)
        
        async def main():
            try:
                client = TelegramClient(session_path, api_id, api_hash)
                await client.connect()
                
                message = await client.get_messages("me", ids=msg_id)
                if not message or not message.file:
                    return None, None, None
                
                file_bytes = await message.download_media(bytes)
                mime_type = message.file.mime_type or 'application/octet-stream'
                file_name = message.file.name or f"file_{msg_id}"
                
                await client.disconnect()
                return file_bytes, mime_type, file_name
                
            except Exception as e:
                logger.error(f"GET FILE ERROR: {e}")
                return None, None, None

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        file_bytes, mime_type, file_name = loop.run_until_complete(main())
        
        if file_bytes is None:
            return "File not found", 404
        
        from flask import Response
        return Response(file_bytes, mimetype=mime_type, headers={
            'Content-Disposition': f'inline; filename="{file_name}"'
        })
        
    except Exception as e:
        logger.error(f"GET FILE ERROR: {e}")
        return "File not found", 404

@app.route('/logout', methods=['POST'])
@rate_limit
def logout():
    """Logout user and clear session"""
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        
        if phone:
            # Remove session
            session_path = get_session_path(phone)
            if os.path.exists(session_path):
                os.remove(session_path)
            
            # Clear from memory
            if phone in session_timestamps:
                del session_timestamps[phone]
            if phone in phone_code_hashes:
                del phone_code_hashes[phone]
            
            log_security_event("LOGOUT", f"User logged out", phone)
        
        return jsonify({"status": "success"})
        
    except Exception as e:
        logger.error(f"LOGOUT ERROR: {e}")
        return jsonify({"status": "error", "message": "Logout failed"}), 500

@app.route('/delete_data', methods=['POST'])
@rate_limit
def delete_data():
    """Delete all user data (GDPR compliance)"""
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        
        if phone:
            # Remove session
            session_path = get_session_path(phone)
            if os.path.exists(session_path):
                os.remove(session_path)
            
            # Clear from memory
            if phone in session_timestamps:
                del session_timestamps[phone]
            if phone in phone_code_hashes:
                del phone_code_hashes[phone]
            
            # Remove from user folders
            user_folders = load_user_folders()
            if phone in user_folders:
                del user_folders[phone]
                save_user_folders(user_folders)
            
            log_security_event("DATA_DELETED", f"All data deleted for user", phone)
        
        return jsonify({"status": "success", "message": "All data deleted"})
        
    except Exception as e:
        logger.error(f"DELETE DATA ERROR: {e}")
        return jsonify({"status": "error", "message": "Data deletion failed"}), 500

if __name__ == '__main__':
    logger.info("🚀 Starting Telegram file storage application")
    logger.info("🌐 Running on http://127.0.0.1:5000")
    
    # Clean up expired sessions on startup
    cleanup_expired_sessions()
    
    app.run(host='127.0.0.1', port=5000, debug=False) 
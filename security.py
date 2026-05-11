from flask import request, jsonify
from functools import wraps
import time
import re
import hashlib
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiting storage
rate_limit_storage = defaultdict(list)
MAX_REQUESTS_PER_MINUTE = 10
MAX_REQUESTS_PER_HOUR = 100

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get client IP
        client_ip = request.remote_addr
        
        # Clean old entries
        current_time = time.time()
        rate_limit_storage[client_ip] = [
            req_time for req_time in rate_limit_storage[client_ip] 
            if current_time - req_time < 3600  # Keep last hour
        ]
        
        # Check rate limits
        if len(rate_limit_storage[client_ip]) >= MAX_REQUESTS_PER_HOUR:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
        
        # Add current request
        rate_limit_storage[client_ip].append(current_time)
        
        return f(*args, **kwargs)
    return decorated_function

def validate_phone_number(phone):
    """Validate phone number format"""
    if not phone:
        return False, "Phone number is required"
    
    # Remove spaces and dashes
    phone = re.sub(r'[\s\-]', '', phone)
    
    # Check format: +[country code][number]
    if not re.match(r'^\+[1-9]\d{1,14}$', phone):
        return False, "Invalid phone number format. Use +[country code][number]"
    
    return True, phone

def validate_file_upload(file):
    """Validate file upload"""
    if not file:
        return False, "No file provided"
    
    # Check file size (2GB — Telegram's own limit)
    MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024
    if hasattr(file, 'content_length') and file.content_length and file.content_length > MAX_FILE_SIZE:
        return False, "File too large. Maximum size is 2GB"
    
    # Check file extension
    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'svg',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'zip', 'rar', '7z', 'tar', 'gz', 'tgz',
        'mp3', 'mp4', 'avi', 'mov', 'wmv', 'mkv', 'flac', 'aac', 'ogg',
        'apk', 'iso', 'dmg',
    }
    
    filename = file.filename
    if not filename or '.' not in filename:
        return False, "Invalid filename"
    
    extension = filename.rsplit('.', 1)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        return False, f"File type .{extension} not allowed"
    
    return True, filename

def sanitize_input(text):
    """Sanitize user input"""
    if not text:
        return ""
    
    # Remove potentially dangerous characters
    text = re.sub(r'[<>"\']', '', text)
    return text.strip()

def log_security_event(event_type, details, user_phone=None):
    """Log security events"""
    log_entry = {
        'timestamp': time.time(),
        'event_type': event_type,
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'user_phone': user_phone,
        'details': details
    }
    
    logger.info(f"SECURITY EVENT: {log_entry}")

 
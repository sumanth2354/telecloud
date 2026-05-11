from flask import (
    Flask, request, jsonify, send_from_directory,
    Response, redirect, make_response
)
from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
import os
import asyncio
import threading
import uuid
import json
import secrets
from dotenv import load_dotenv
import time
import hashlib
import logging
from functools import wraps
from cryptography.fernet import Fernet
from security import (
    rate_limit, validate_phone_number, validate_file_upload,
    sanitize_input, log_security_event
)

load_dotenv()

api_id_env = os.getenv("API_ID")
api_hash_env = os.getenv("API_HASH")
api_id = int(api_id_env) if api_id_env and str(api_id_env).strip().isdigit() else None
api_hash = api_hash_env if api_hash_env and str(api_hash_env).strip() else None

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set for Flask application")
cipher = Fernet(SECRET_KEY.encode())

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB upload limit

# Configuration
UPLOAD_FOLDER = 'uploads'
SESSIONS_FOLDER = 'sessions'
THUMB_FOLDER = 'thumbs'
FOLDERS_FILE = 'user_folders.json'
API_SESSIONS_FILE = 'api_sessions.json'
SESSION_TIMEOUT = 3600
CACHE_TTL = 300
PAGE_SIZE = 50
IS_SECURE = os.getenv("SECURE_COOKIES", "false").lower() == "true"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SESSIONS_FOLDER, exist_ok=True)
os.makedirs(THUMB_FOLDER, exist_ok=True)


def load_api_sessions():
    if os.path.exists(API_SESSIONS_FILE):
        try:
            with open(API_SESSIONS_FILE, 'rb') as f:
                encrypted_data = f.read()
            decrypted_data = cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception:
            # Fallback for unencrypted data or errors
            try:
                with open(API_SESSIONS_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                logger.error("Error reading api sessions file")
    return {}


def save_api_sessions(data):
    try:
        json_data = json.dumps(data).encode()
        encrypted_data = cipher.encrypt(json_data)
        with open(API_SESSIONS_FILE, 'wb') as f:
            f.write(encrypted_data)
    except Exception as e:
        logger.error(f"Error saving api sessions: {e}")


def _purge_api_session(sid):
    """Remove a single API-session entry from encrypted disk storage."""
    if not sid:
        return
    try:
        sessions = load_api_sessions()
        if sid in sessions:
            sessions.pop(sid)
            save_api_sessions(sessions)
    except Exception as e:
        logger.error(f"PURGE API SESSION ERROR: {e}")


def _get_api_session_id():
    sid = request.cookies.get("tc_api_session")
    return sid if sid and isinstance(sid, str) and len(sid) >= 16 else None


def get_request_api_credentials():
    """
    Resolve Telegram API credentials for the current visitor.
    Priority:
      1) credentials stored server-side for tc_api_session cookie
      2) environment API_ID/API_HASH (backward compatible)
    """
    sid = _get_api_session_id()
    if sid:
        sessions = load_api_sessions()
        entry = sessions.get(sid)
        if entry and entry.get("api_id") and entry.get("api_hash"):
            try:
                return int(entry["api_id"]), str(entry["api_hash"])
            except Exception:
                pass
    if api_id and api_hash:
        return api_id, api_hash
    return None, None


def validate_api_credentials_input(api_id_value, api_hash_value):
    try:
        api_id_int = int(api_id_value)
    except Exception:
        return False, "API ID must be a number", None, None

    if api_id_int <= 0:
        return False, "API ID must be a positive number", None, None

    api_hash_str = str(api_hash_value or "").strip()
    if not api_hash_str:
        return False, "API Hash is required", None, None

    # Telegram API hash is typically 32 hex chars; keep permissive but reject obvious garbage.
    if len(api_hash_str) < 16:
        return False, "API Hash looks too short", None, None

    return True, None, api_id_int, api_hash_str

# Pre-auth state (needed during login flow only)
phone_code_hashes = {}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ── Persistent event loop ─────────────────────────────────────────
_loop = asyncio.new_event_loop()
threading.Thread(target=_loop.run_forever, daemon=True).start()


def run_async(coro):
    return asyncio.run_coroutine_threadsafe(coro, _loop).result(timeout=120)


# ── Reusable Telegram client pool ─────────────────────────────────
_clients = {}


async def get_client(phone, require_authorized=False):
    if phone in _clients:
        client = _clients[phone]
        if client.is_connected():
            if require_authorized and not await client.is_user_authorized():
                try:
                    await client.disconnect()
                except Exception:
                    pass
                _clients.pop(phone, None)
            else:
                return client
        try:
            await client.connect()
            if require_authorized and not await client.is_user_authorized():
                await client.disconnect()
                _clients.pop(phone, None)
            else:
                return client
        except Exception:
            _clients.pop(phone, None)

    session_path = get_session_path(phone)
    req_api_id, req_api_hash = get_request_api_credentials()
    if not req_api_id or not req_api_hash:
        raise Exception("Telegram API credentials not configured. Please complete setup first.")
    client = TelegramClient(session_path, req_api_id, req_api_hash)
    await client.connect()
    if require_authorized and not await client.is_user_authorized():
        await client.disconnect()
        raise Exception("Telegram session not authorized. Please login again.")
    _clients[phone] = client
    return client


async def remove_client(phone):
    client = _clients.pop(phone, None)
    if client:
        try:
            await client.disconnect()
        except Exception:
            pass


# ── Metadata cache ────────────────────────────────────────────────
_cache = {}


def cache_get(key):
    if key in _cache:
        data, ts = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return data
        del _cache[key]
    return None


def cache_set(key, data):
    _cache[key] = (data, time.time())


def cache_invalidate(phone):
    for k in [k for k in _cache if k.startswith(f"{phone}:")]:
        del _cache[k]


# ── Server-side auth sessions ─────────────────────────────────────
_sessions = {}  # token -> {phone, created_at, last_active}


def create_session(phone):
    token = secrets.token_urlsafe(32)
    _sessions[token] = {
        'phone': phone,
        'created_at': time.time(),
        'last_active': time.time()
    }
    return token


def get_session_data(token):
    if not token or token not in _sessions:
        return None
    sess = _sessions[token]
    if time.time() - sess['last_active'] > SESSION_TIMEOUT:
        del _sessions[token]
        return None
    sess['last_active'] = time.time()
    return sess


def destroy_session(token):
    _sessions.pop(token, None)


def require_auth(f):
    """Decorator: rejects 401 if no valid session; sets request.phone."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session_token')
        sess = get_session_data(token)
        if not sess:
            return jsonify({"status": "error", "message": "Not authenticated"}), 401
        request.phone = sess['phone']
        return f(*args, **kwargs)
    return decorated


# ── CSRF protection (double-submit cookie) ────────────────────────

@app.before_request
def csrf_check():
    if request.method not in ('POST', 'PUT', 'DELETE', 'PATCH'):
        return
    cookie_val = request.cookies.get('csrf_token')
    header_val = request.headers.get('X-CSRF-Token')
    if not cookie_val or cookie_val != header_val:
        return jsonify({"status": "error", "message": "CSRF validation failed"}), 403


@app.after_request
def set_csrf_cookie(response):
    if 'csrf_token' not in request.cookies:
        token = secrets.token_urlsafe(32)
        response.set_cookie(
            'csrf_token', token,
            httponly=False, samesite='Lax',
            secure=IS_SECURE, max_age=86400, path='/'
        )
    return response


# ── Helpers ────────────────────────────────────────────────────────

def get_session_path(phone):
    phone_hash = hashlib.sha256(phone.encode()).hexdigest()
    return os.path.join(SESSIONS_FOLDER, f"{phone_hash}.session")


def cleanup_expired_sessions():
    now = time.time()
    expired_tokens = [t for t, s in _sessions.items()
                      if now - s['last_active'] > SESSION_TIMEOUT]
    expired_phones = set()
    for t in expired_tokens:
        expired_phones.add(_sessions[t]['phone'])
        del _sessions[t]

    for phone in expired_phones:
        still_active = any(s['phone'] == phone for s in _sessions.values())
        if not still_active:
            path = get_session_path(phone)
            if os.path.exists(path):
                os.remove(path)
            phone_code_hashes.pop(phone, None)
            try:
                run_async(remove_client(phone))
            except Exception:
                pass
            cache_invalidate(phone)
            logger.info(f"Cleaned up expired session for {phone}")


def load_user_folders():
    if os.path.exists(FOLDERS_FILE):
        try:
            with open(FOLDERS_FILE, 'rb') as f:
                encrypted_data = f.read()
            return json.loads(cipher.decrypt(encrypted_data))
        except Exception:
            try:
                with open(FOLDERS_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                logger.error("Error reading user folders file")
    return {}


def save_user_folders(folders_data):
    try:
        encrypted = cipher.encrypt(json.dumps(folders_data).encode())
        with open(FOLDERS_FILE, 'wb') as f:
            f.write(encrypted)
    except Exception as e:
        logger.error(f"Error saving user folders: {e}")


def categorize_saved_file(file_name, mime_type):
    file_name = (file_name or "").lower()
    mime_type = (mime_type or "").lower()
    if file_name.endswith(".apk") or mime_type == "application/vnd.android.package-archive":
        return "APK"
    if mime_type.startswith("image/"):
        return "Images"
    if mime_type.startswith("video/"):
        return "Videos"
    if mime_type.startswith("audio/"):
        return "Audio"
    if any(file_name.endswith(ext) for ext in (
        ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"
    )):
        return "Documents"
    if "pdf" in mime_type:
        return "Documents"
    if any(file_name.endswith(ext) for ext in (
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz"
    )):
        return "Archives"
    return "Other"


# ── Page routes ────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('.', 'consent.html')


@app.route('/privacy-policy')
def privacy_policy():
    return send_from_directory('.', 'privacy_policy.html')


@app.route('/setup')
def setup_page():
    return send_from_directory('.', 'setup.html')


@app.route('/login')
def login():
    token = request.cookies.get('session_token')
    if get_session_data(token):
        return redirect('/upload-page')
    req_api_id, req_api_hash = get_request_api_credentials()
    if not req_api_id or not req_api_hash:
        return redirect('/setup')
    return send_from_directory('.', 'login.html')


@app.route('/upload-page')
def upload_page():
    token = request.cookies.get('session_token')
    if not get_session_data(token):
        return redirect('/login')
    return send_from_directory('.', 'upload.html')


@app.route('/setup-api', methods=['POST'])
@rate_limit
def setup_api():
    """
    Store user-provided Telegram API credentials server-side and bind them to this visitor
    via an HttpOnly cookie, so existing pages can work unchanged.
    """
    try:
        data = request.get_json() or {}
        ok, err, api_id_int, api_hash_str = validate_api_credentials_input(
            data.get("api_id"), data.get("api_hash")
        )
        if not ok:
            return jsonify({"status": "error", "message": err}), 400

        sid = _get_api_session_id() or secrets.token_urlsafe(32)

        sessions = load_api_sessions()
        sessions[sid] = {
            "api_id": api_id_int,
            "api_hash": api_hash_str,
            "created_at": time.time(),
            "ip": request.remote_addr,
            "ua": request.headers.get("User-Agent", "")
        }

        ttl = int(os.getenv("API_SESSION_TTL", "604800 "))  # 7 days
        now = time.time()
        if ttl > 0:
            sessions = {
                k: v for k, v in sessions.items()
                if (now - float(v.get("created_at", now))) < ttl
            }
            sessions[sid] = {
                "api_id": api_id_int,
                "api_hash": api_hash_str,
                "created_at": now,
                "ip": request.remote_addr,
                "ua": request.headers.get("User-Agent", "")
            }

        save_api_sessions(sessions)

        resp = make_response(jsonify({"status": "success"}))
        resp.set_cookie(
            "tc_api_session",
            sid,
            httponly=True,
            secure=IS_SECURE,
            samesite="Lax",
            max_age=ttl if ttl > 0 else None,
            path="/"
        )
        return resp
    except Exception as e:
        logger.error(f"SETUP API ERROR: {e}")
        return jsonify({"status": "error", "message": "Setup failed"}), 500


@app.route('/me')
@require_auth
def me():
    """Return the authenticated user's phone (for frontend display)."""
    return jsonify({"phone": request.phone})


# ── Auth routes (pre-login, phone comes from request body) ────────

@app.route('/send_code', methods=['POST'])
@rate_limit
def send_code():
    try:
        req_api_id, req_api_hash = get_request_api_credentials()
        if not req_api_id or not req_api_hash:
            return jsonify({
                "status": "error",
                "message": "Telegram API credentials not configured. Please complete setup first.",
                "setup_url": "/setup"
            }), 400

        data = request.get_json()
        phone = data.get('phone') if data else None

        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            log_security_event("INVALID_PHONE", f"Invalid phone format: {phone}")
            return jsonify({"status": "error", "message": result}), 400
        phone = result
        cleanup_expired_sessions()

        async def _do():
            client = await get_client(phone)
            r = await client.send_code_request(phone)
            phone_code_hashes[phone] = r.phone_code_hash
            log_security_event("OTP_SENT", f"OTP sent to {phone}", phone)
            return {
                "status": "code_sent",
                "message": f"OTP sent to {phone}. Check your Telegram app."
            }

        return jsonify(run_async(_do()))
    except Exception as e:
        logger.error(f"SEND CODE ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to send OTP"}), 500


@app.route('/verify_code', methods=['POST'])
@rate_limit
def verify_code():
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        code = data.get('code') if data else None

        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            return jsonify({"status": "error", "message": result}), 400
        phone = result
        code = sanitize_input(code)
        if not code:
            return jsonify({"status": "error", "message": "OTP code is required"}), 400

        async def _do():
            try:
                client = await get_client(phone)
                pch = phone_code_hashes.get(phone)
                if not pch:
                    return {"status": "failed", "error": "No code hash. Request OTP again."}
                await client.sign_in(phone=phone, code=code, phone_code_hash=pch)
                log_security_event("LOGIN_SUCCESS", "Logged in", phone)
                return {"status": "success"}
            except SessionPasswordNeededError:
                log_security_event("2FA_REQUIRED", "2FA required", phone)
                return {"status": "2fa_required"}
            except Exception as e:
                logger.error(f"VERIFY CODE ERROR: {e}")
                log_security_event("LOGIN_FAILED", str(e), phone)
                return {"status": "failed", "error": "Invalid OTP or session expired"}

        result = run_async(_do())

        # On successful login: issue session + rotate CSRF token
        if result.get('status') == 'success':
            token = create_session(phone)
            csrf = secrets.token_urlsafe(32)
            resp = make_response(jsonify(result))
            resp.set_cookie(
                'session_token', token,
                httponly=True, samesite='Lax',
                secure=IS_SECURE, max_age=SESSION_TIMEOUT, path='/'
            )
            resp.set_cookie(
                'csrf_token', csrf,
                httponly=False, samesite='Lax',
                secure=IS_SECURE, max_age=86400, path='/'
            )
            return resp

        return jsonify(result)
    except Exception as e:
        logger.error(f"Unexpected error in verify_code: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.route('/verify_password', methods=['POST'])
@rate_limit
def verify_password():
    try:
        data = request.get_json()
        phone = data.get('phone') if data else None
        password = data.get('password') if data else None

        is_valid, result = validate_phone_number(phone)
        if not is_valid:
            return jsonify({"status": "error", "message": result}), 400
        phone = result
        password = sanitize_input(password)
        if not password:
            return jsonify({"status": "error", "message": "Password is required"}), 400

        async def _do():
            try:
                client = await get_client(phone)
                if not await client.is_user_authorized():
                    await client.sign_in(password=password)
                log_security_event("2FA_SUCCESS", "2FA verified", phone)
                return {"status": "success"}
            except Exception as e:
                logger.error(f"VERIFY PASSWORD ERROR: {e}")
                log_security_event("2FA_FAILED", str(e), phone)
                return {"status": "failed", "error": "Invalid password"}

        result = run_async(_do())

        if result.get('status') == 'success':
            token = create_session(phone)
            csrf = secrets.token_urlsafe(32)
            resp = make_response(jsonify(result))
            resp.set_cookie(
                'session_token', token,
                httponly=True, samesite='Lax',
                secure=IS_SECURE, max_age=SESSION_TIMEOUT, path='/'
            )
            resp.set_cookie(
                'csrf_token', csrf,
                httponly=False, samesite='Lax',
                secure=IS_SECURE, max_age=86400, path='/'
            )
            return resp

        return jsonify(result)
    except Exception as e:
        logger.error(f"Unexpected error in verify_password: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500


# ── Authenticated endpoints (phone from session, not body) ────────

@app.route('/upload', methods=['POST'])
@rate_limit
@require_auth
def upload():
    try:
        phone = request.phone
        folder_name = request.form.get('folderName')
        files = request.files.getlist('file')

        folder_name = sanitize_input(folder_name)
        if not files:
            return jsonify({"status": "error", "message": "No files provided"}), 400

        for file in files:
            is_valid, result = validate_file_upload(file)
            if not is_valid:
                return jsonify({"status": "error", "message": result}), 400

        saved = []
        for file in files:
            filename = f"{uuid.uuid4().hex}_{file.filename}"
            path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(path)
            saved.append((file.filename, path))

        async def _do():
            client = await get_client(phone, require_authorized=True)
            uploaded = []
            for orig_name, path in saved:
                try:
                    await client.send_file(
                        "me", path,
                        caption=folder_name or "",
                        force_document=True
                    )
                    uploaded.append(orig_name)
                except Exception as e:
                    logger.error(f"Error uploading {orig_name}: {e}")
                    raise
                finally:
                    if os.path.exists(path):
                        os.remove(path)
            log_security_event("FILES_UPLOADED", f"Uploaded {len(uploaded)} files", phone)
            return {"status": "success", "files": uploaded}

        result = run_async(_do())

        if folder_name:
            user_folders = load_user_folders()
            if phone not in user_folders:
                user_folders[phone] = []
            if folder_name not in user_folders[phone]:
                user_folders[phone].append(folder_name)
                save_user_folders(user_folders)

        cache_invalidate(phone)
        return jsonify(result)
    except Exception as e:
        logger.error(f"UPLOAD ERROR: {e}")
        return jsonify({"status": "error", "message": "Upload failed"}), 500


@app.route('/list_folders', methods=['POST'])
@rate_limit
@require_auth
def list_folders():
    try:
        phone = request.phone
        user_folders = load_user_folders()
        folder_list = user_folders.get(phone, [])
        log_security_event("FOLDERS_LISTED", f"Listed {len(folder_list)} folders", phone)
        return jsonify({"status": "success", "folders": sorted(folder_list)})
    except Exception as e:
        logger.error(f"LIST FOLDERS ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to list folders"}), 500


@app.route('/create_folder', methods=['POST'])
@rate_limit
@require_auth
def create_folder():
    try:
        phone = request.phone
        data = request.get_json() or {}
        folder_name = sanitize_input(data.get('folder_name'))

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
@require_auth
def list_files_in_folder():
    try:
        phone = request.phone
        data = request.get_json() or {}
        folder = sanitize_input(data.get('folder'))
        if not folder:
            return jsonify({"status": "error", "message": "Folder name is required"}), 400

        cache_key = f"{phone}:folder:{folder}"
        cached = cache_get(cache_key)
        if cached is not None:
            return jsonify({"status": "success", "files": cached})

        async def _do():
            client = await get_client(phone, require_authorized=True)
            messages = await client.get_messages("me", limit=200)
            files = []
            for msg in messages:
                if msg.file and msg.text and msg.text.strip() == folder:
                    files.append({
                        "id": msg.id,
                        "name": msg.file.name,
                        "size": msg.file.size,
                        "mime_type": msg.file.mime_type,
                        "date": msg.date.isoformat()
                    })
            return files

        files = run_async(_do())
        cache_set(cache_key, files)
        log_security_event("FILES_LISTED", f"Listed {len(files)} files in {folder}", phone)
        return jsonify({"status": "success", "files": files})
    except Exception as e:
        logger.error(f"LIST FILES IN FOLDER ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to list files"}), 500


@app.route('/list_all_files', methods=['POST'])
@rate_limit
@require_auth
def list_all_files():
    try:
        phone = request.phone
        data = request.get_json() or {}
        offset = int(data.get('offset', 0))
        limit = int(data.get('limit', PAGE_SIZE))
        category = data.get('category', 'All')
        refresh = data.get('refresh', False)

        cache_key = f"{phone}:all_files"
        if refresh:
            cache_invalidate(phone)

        all_files = cache_get(cache_key)

        if all_files is None:
            max_raw = os.getenv("MAX_SCAN_MESSAGES", "2000")
            max_scan = None if str(max_raw).strip() == "0" else int(max_raw)

            async def _do():
                client = await get_client(phone, require_authorized=True)
                files = []
                seen = set()
                async for msg in client.iter_messages("me", limit=max_scan):
                    if not msg or not msg.file or msg.id in seen:
                        continue
                    seen.add(msg.id)
                    name = msg.file.name or f"file_{msg.id}"
                    mime = msg.file.mime_type or "application/octet-stream"
                    files.append({
                        "id": msg.id,
                        "name": name,
                        "size": msg.file.size or 0,
                        "mime_type": mime,
                        "date": msg.date.isoformat() if msg.date else None,
                        "category": categorize_saved_file(name, mime)
                    })
                files.sort(key=lambda x: x.get("date") or "", reverse=True)
                return files

            all_files = run_async(_do())
            cache_set(cache_key, all_files)

        if category and category != 'All':
            filtered = [f for f in all_files if f.get('category') == category]
        else:
            filtered = all_files

        page = filtered[offset:offset + limit]

        log_security_event("ALL_FILES_LISTED",
                           f"Listed files (offset={offset}, cat={category})", phone)
        return jsonify({
            "status": "success",
            "files": page,
            "total": len(filtered),
            "has_more": offset + limit < len(filtered)
        })
    except Exception as e:
        logger.error(f"LIST ALL FILES ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to list files"}), 500


@app.route('/move_files_to_folder', methods=['POST'])
@rate_limit
@require_auth
def move_files_to_folder():
    try:
        phone = request.phone
        data = request.get_json() or {}
        folder = sanitize_input(data.get('folder', '')).strip()
        msg_ids = data.get('msg_ids')

        if not folder:
            return jsonify({"status": "error", "message": "Folder name is required"}), 400
        if not isinstance(msg_ids, list) or not msg_ids:
            return jsonify({"status": "error", "message": "msg_ids must be a non-empty list"}), 400
        try:
            msg_ids_int = [int(x) for x in msg_ids]
        except Exception:
            return jsonify({"status": "error", "message": "msg_ids must contain integers"}), 400

        async def _do():
            client = await get_client(phone, require_authorized=True)
            moved, failed = 0, []
            for mid in msg_ids_int:
                try:
                    await client.edit_message("me", mid, folder)
                    moved += 1
                except Exception as e:
                    logger.error(f"MOVE FILE ERROR msg_id={mid}: {e}")
                    failed.append(mid)
            return {"status": "success", "moved": moved, "failed": failed}

        result = run_async(_do())

        try:
            user_folders = load_user_folders()
            if phone not in user_folders:
                user_folders[phone] = []
            if folder not in user_folders[phone]:
                user_folders[phone].append(folder)
                save_user_folders(user_folders)
        except Exception as e:
            logger.error(f"Error persisting folder on move: {e}")

        cache_invalidate(phone)
        log_security_event("FILES_MOVED",
                           f"Moved {result['moved']} files to {folder}", phone)
        return jsonify(result)
    except Exception as e:
        logger.error(f"MOVE FILES ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to move files"}), 500


@app.route('/delete_files', methods=['POST'])
@rate_limit
@require_auth
def delete_files():
    try:
        phone = request.phone
        data = request.get_json() or {}
        msg_ids = data.get('msg_ids')

        if not isinstance(msg_ids, list) or not msg_ids:
            return jsonify({"status": "error", "message": "msg_ids must be a non-empty list"}), 400
        try:
            msg_ids_int = [int(x) for x in msg_ids]
        except Exception:
            return jsonify({"status": "error", "message": "msg_ids must contain integers"}), 400

        async def _do():
            client = await get_client(phone, require_authorized=True)
            deleted, failed = 0, []
            for i in range(0, len(msg_ids_int), 100):
                chunk = msg_ids_int[i:i + 100]
                try:
                    await client.delete_messages("me", chunk)
                    deleted += len(chunk)
                except Exception as e:
                    logger.error(f"DELETE FILES ERROR chunk={chunk}: {e}")
                    failed.extend(chunk)
            return {"status": "success", "deleted": deleted, "failed": failed}

        result = run_async(_do())

        phone_hash = hashlib.sha256(phone.encode()).hexdigest()[:16]
        for mid in msg_ids_int:
            tp = os.path.join(THUMB_FOLDER, f"{phone_hash}_{mid}.jpg")
            if os.path.exists(tp):
                os.remove(tp)

        cache_invalidate(phone)
        log_security_event("FILES_DELETED", f"Deleted {result['deleted']} files", phone)
        return jsonify(result)
    except Exception as e:
        logger.error(f"DELETE FILES ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to delete files"}), 500


# ── Stats ─────────────────────────────────────────────────────────

@app.route('/folder_counts', methods=['POST'])
@rate_limit
@require_auth
def folder_counts():
    """Return file counts per folder + total storage stats."""
    try:
        phone = request.phone
        cache_key = f"{phone}:folder_counts"
        cached = cache_get(cache_key)
        if cached is not None:
            return jsonify({"status": "success", **cached})

        user_folders = load_user_folders()
        folder_list = user_folders.get(phone, [])

        async def _do():
            client = await get_client(phone, require_authorized=True)
            counts = {f: 0 for f in folder_list}
            total_size = 0
            total_files = 0
            async for msg in client.iter_messages("me", limit=500):
                if not msg or not msg.file:
                    continue
                total_files += 1
                total_size += msg.file.size or 0
                if msg.text:
                    caption = msg.text.strip()
                    if caption in counts:
                        counts[caption] += 1
            return {"counts": counts, "total_files": total_files, "total_size": total_size}

        result = run_async(_do())
        cache_set(cache_key, result)
        return jsonify({"status": "success", **result})
    except Exception as e:
        logger.error(f"FOLDER COUNTS ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to get counts"}), 500


# ── Folder management ─────────────────────────────────────────────

@app.route('/rename_folder', methods=['POST'])
@rate_limit
@require_auth
def rename_folder():
    try:
        phone = request.phone
        data = request.get_json() or {}
        old_name = sanitize_input(data.get('old_name', '')).strip()
        new_name = sanitize_input(data.get('new_name', '')).strip()

        if not old_name or not new_name:
            return jsonify({"status": "error", "message": "Both old and new names are required"}), 400
        if old_name == new_name:
            return jsonify({"status": "error", "message": "Names are the same"}), 400

        user_folders = load_user_folders()
        if phone not in user_folders or old_name not in user_folders[phone]:
            return jsonify({"status": "error", "message": "Folder not found"}), 404
        if new_name in user_folders[phone]:
            return jsonify({"status": "error", "message": "A folder with that name already exists"}), 400

        async def _do():
            client = await get_client(phone, require_authorized=True)
            messages = await client.get_messages("me", limit=500)
            renamed = 0
            for msg in messages:
                if msg.file and msg.text and msg.text.strip() == old_name:
                    try:
                        await client.edit_message("me", msg.id, new_name)
                        renamed += 1
                    except Exception as e:
                        logger.error(f"RENAME FILE CAPTION ERROR msg_id={msg.id}: {e}")
            return renamed

        renamed = run_async(_do())

        idx = user_folders[phone].index(old_name)
        user_folders[phone][idx] = new_name
        save_user_folders(user_folders)
        cache_invalidate(phone)

        log_security_event("FOLDER_RENAMED",
                           f"Renamed '{old_name}' to '{new_name}' ({renamed} files)", phone)
        return jsonify({"status": "success", "renamed_files": renamed})
    except Exception as e:
        logger.error(f"RENAME FOLDER ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to rename folder"}), 500


@app.route('/delete_folder', methods=['POST'])
@rate_limit
@require_auth
def delete_folder():
    """Remove a folder label. Files stay in Telegram untouched."""
    try:
        phone = request.phone
        data = request.get_json() or {}
        folder_name = sanitize_input(data.get('folder_name', '')).strip()

        if not folder_name:
            return jsonify({"status": "error", "message": "Folder name is required"}), 400

        user_folders = load_user_folders()
        if phone not in user_folders or folder_name not in user_folders[phone]:
            return jsonify({"status": "error", "message": "Folder not found"}), 404

        user_folders[phone].remove(folder_name)
        save_user_folders(user_folders)
        cache_invalidate(phone)

        log_security_event("FOLDER_DELETED", f"Deleted folder: {folder_name}", phone)
        return jsonify({"status": "success", "message": "Folder removed. Files are still in Telegram."})
    except Exception as e:
        logger.error(f"DELETE FOLDER ERROR: {e}")
        return jsonify({"status": "error", "message": "Failed to delete folder"}), 500


@app.route('/search_files', methods=['POST'])
@rate_limit
@require_auth
def search_files():
    """Search files by name across all Saved Messages."""
    try:
        phone = request.phone
        data = request.get_json() or {}
        query = data.get('query', '').strip().lower()

        if not query or len(query) < 2:
            return jsonify({"status": "error", "message": "Query must be at least 2 characters"}), 400

        # Reuse the all_files cache if available
        cache_key = f"{phone}:all_files"
        all_files = cache_get(cache_key)

        if all_files is None:
            max_raw = os.getenv("MAX_SCAN_MESSAGES", "2000")
            max_scan = None if str(max_raw).strip() == "0" else int(max_raw)

            async def _do():
                client = await get_client(phone, require_authorized=True)
                files = []
                seen = set()
                async for msg in client.iter_messages("me", limit=max_scan):
                    if not msg or not msg.file or msg.id in seen:
                        continue
                    seen.add(msg.id)
                    name = msg.file.name or f"file_{msg.id}"
                    mime = msg.file.mime_type or "application/octet-stream"
                    files.append({
                        "id": msg.id,
                        "name": name,
                        "size": msg.file.size or 0,
                        "mime_type": mime,
                        "date": msg.date.isoformat() if msg.date else None,
                        "category": categorize_saved_file(name, mime)
                    })
                files.sort(key=lambda x: x.get("date") or "", reverse=True)
                return files

            all_files = run_async(_do())
            cache_set(cache_key, all_files)

        results = [f for f in all_files if query in (f.get('name') or '').lower()]

        log_security_event("FILES_SEARCHED", f"Query='{query}', found {len(results)}", phone)
        return jsonify({
            "status": "success",
            "files": results[:200],
            "total": len(results),
            "query": query
        })
    except Exception as e:
        logger.error(f"SEARCH FILES ERROR: {e}")
        return jsonify({"status": "error", "message": "Search failed"}), 500


# ── File serving (phone from session, not URL) ────────────────────

@app.route('/get_file/<int:msg_id>')
@require_auth
def get_file(msg_id):
    try:
        phone = request.phone
        if_none = request.headers.get('If-None-Match')
        etag = f'"{msg_id}"'
        if if_none == etag:
            return Response(status=304)

        async def _do():
            client = await get_client(phone, require_authorized=True)
            message = await client.get_messages("me", ids=msg_id)
            if not message or not message.file:
                return None, None, None
            file_bytes = await message.download_media(bytes)
            mime = message.file.mime_type or 'application/octet-stream'
            name = message.file.name or f"file_{msg_id}"
            return file_bytes, mime, name

        file_bytes, mime, name = run_async(_do())
        if file_bytes is None:
            return "File not found", 404

        resp = Response(file_bytes, mimetype=mime)
        resp.headers['Content-Disposition'] = f'inline; filename="{name}"'
        resp.headers['Cache-Control'] = 'public, max-age=86400'
        resp.headers['ETag'] = etag
        return resp
    except Exception as e:
        logger.error(f"GET FILE ERROR: {e}")
        return "File not found", 404


@app.route('/get_thumbnail/<int:msg_id>')
@require_auth
def get_thumbnail(msg_id):
    try:
        phone = request.phone
        phone_hash = hashlib.sha256(phone.encode()).hexdigest()[:16]
        thumb_file = f"{phone_hash}_{msg_id}.jpg"
        thumb_path = os.path.join(os.path.abspath(THUMB_FOLDER), thumb_file)

        if os.path.exists(thumb_path):
            resp = send_from_directory(
                os.path.abspath(THUMB_FOLDER), thumb_file,
                mimetype='image/jpeg'
            )
            resp.headers['Cache-Control'] = 'public, max-age=604800'
            return resp

        async def _do():
            client = await get_client(phone, require_authorized=True)
            message = await client.get_messages("me", ids=msg_id)
            if not message or not message.file:
                return None

            if message.document and getattr(message.document, 'thumbs', None):
                try:
                    data = await message.download_media(bytes, thumb=0)
                    if data:
                        return data
                except Exception:
                    pass

            if message.photo:
                try:
                    data = await message.download_media(bytes, thumb=0)
                    if data:
                        return data
                except Exception:
                    pass

            mime = message.file.mime_type or ''
            if mime.startswith('image/') and message.file.size and message.file.size < 500_000:
                return await message.download_media(bytes)

            return None

        thumb_bytes = run_async(_do())
        if not thumb_bytes:
            return "Not found", 404

        with open(thumb_path, 'wb') as f:
            f.write(thumb_bytes)

        resp = Response(thumb_bytes, mimetype='image/jpeg')
        resp.headers['Cache-Control'] = 'public, max-age=604800'
        return resp
    except Exception as e:
        logger.error(f"GET THUMBNAIL ERROR: {e}")
        return "Not found", 404


# ── Logout / data deletion (no require_auth — must work even if expired) ──

@app.route('/logout', methods=['POST'])
@rate_limit
def logout():
    try:
        token = request.cookies.get('session_token')
        api_sid = request.cookies.get('tc_api_session')
        sess = get_session_data(token) if token else None
        phone = sess['phone'] if sess else None

        if token:
            destroy_session(token)
        if phone:
            try:
                run_async(remove_client(phone))
            except Exception:
                pass
            path = get_session_path(phone)
            if os.path.exists(path):
                os.remove(path)
            phone_code_hashes.pop(phone, None)
            cache_invalidate(phone)
            log_security_event("LOGOUT", "User logged out", phone)

        # Purge API credentials so next visit requires re-setup
        _purge_api_session(api_sid)

        resp = make_response(jsonify({"status": "success"}))
        resp.delete_cookie('session_token', path='/')
        resp.delete_cookie('csrf_token', path='/')
        resp.delete_cookie('tc_api_session', path='/')
        return resp
    except Exception as e:
        logger.error(f"LOGOUT ERROR: {e}")
        resp = make_response(jsonify({"status": "error", "message": "Logout failed"}))
        resp.delete_cookie('session_token', path='/')
        resp.delete_cookie('csrf_token', path='/')
        resp.delete_cookie('tc_api_session', path='/')
        return resp, 500


@app.route('/delete_data', methods=['POST'])
@rate_limit
@require_auth
def delete_data():
    try:
        phone = request.phone
        token = request.cookies.get('session_token')

        destroy_session(token)

        try:
            run_async(remove_client(phone))
        except Exception:
            pass
        path = get_session_path(phone)
        if os.path.exists(path):
            os.remove(path)
        phone_code_hashes.pop(phone, None)

        user_folders = load_user_folders()
        if phone in user_folders:
            del user_folders[phone]
            save_user_folders(user_folders)

        phone_hash = hashlib.sha256(phone.encode()).hexdigest()[:16]
        for f in os.listdir(THUMB_FOLDER):
            if f.startswith(phone_hash):
                os.remove(os.path.join(THUMB_FOLDER, f))

        cache_invalidate(phone)
        log_security_event("DATA_DELETED", "All data deleted", phone)

        resp = make_response(jsonify({"status": "success", "message": "All data deleted"}))
        resp.delete_cookie('session_token', path='/')
        resp.delete_cookie('csrf_token', path='/')
        return resp
    except Exception as e:
        logger.error(f"DELETE DATA ERROR: {e}")
        return jsonify({"status": "error", "message": "Data deletion failed"}), 500


if __name__ == '__main__':
    logger.info("Starting Telegram file storage application")
    logger.info("Running on http://127.0.0.1:5001")
    cleanup_expired_sessions()
    app.run(host='127.0.0.1', port=5001, debug=False)

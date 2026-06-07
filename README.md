# ☁️ TeleCloud

> **Use your Telegram account as a personal cloud storage.** TeleCloud is a self-hosted web app that lets you upload, organise, search, preview, and download files—all stored securely in your own Telegram "Saved Messages".

---

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Running the App](#running-the-app)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Security](#security)
- [Environment Variables](#environment-variables)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

TeleCloud is a **self-hosted file storage web application** built on top of Telegram's free, unlimited cloud. It uses the [Telethon](https://github.com/LonamiWebs/Telethon) MTProto client to communicate directly with Telegram on behalf of the logged-in user. Files are uploaded to the user's own **Saved Messages** chat, so you own your data 100%—TeleCloud never touches your files.

---

## ✨ Features

| Feature | Description |
|---|---|
| 📁 **Folder Organisation** | Create, rename, and delete virtual folders. Files are tagged with folder names as captions in Telegram. |
| ⬆️ **Multi-File Upload** | Drag-and-drop or browse to upload multiple files at once (up to **2 GB** per file — Telegram's native limit). |
| 🔍 **Search** | Full-name search across all files stored in your Saved Messages. |
| 🗂️ **File Categories** | Automatic categorisation into Images, Videos, Audio, Documents, Archives, APKs, and Other. |
| 👁️ **Preview & Thumbnails** | In-browser preview for images and video thumbnails cached on disk. |
| ⬇️ **Download / Streaming** | Direct file download/streaming from Telegram via the `/get_file/<id>` endpoint. |
| 🔄 **Move Files** | Reassign files to a different folder without re-uploading. |
| 🗑️ **Delete Files** | Permanently delete selected files from your Telegram account. |
| 📊 **Storage Stats** | Per-folder file counts and total storage usage. |
| 🔐 **Secure Auth** | OTP via Telegram + optional 2FA (Two-Step Verification) support. |
| 🛡️ **CSRF Protection** | Double-submit cookie pattern on every mutating endpoint. |
| ⏱️ **Rate Limiting** | Per-IP rate limiting (10 req/min, 100 req/hour) on all endpoints. |
| 🔒 **Encrypted Storage** | Session tokens, API credentials, folder metadata, and share links configuration are AES-encrypted at rest using Fernet. |
| 🔗 **Shareable Links** | Share folders or all files publicly with optional password protection, custom labels, and expiration times. |

---

## 🏗️ Architecture

```
┌─────────────────────────────┐
│         Browser             │
│  HTML + Vanilla JS + CSS    │
│  (login / setup / upload)   │
└────────────┬────────────────┘
             │  HTTP (Flask)
┌────────────▼────────────────┐
│       Flask Backend         │
│  main.py  +  security.py    │
│                             │
│  • Auth sessions (in-mem)   │
│  • Fernet-encrypted storage │
│  • Persistent async loop    │
│  • Metadata cache (TTL=5m)  │
└────────────┬────────────────┘
             │  MTProto (Telethon)
┌────────────▼────────────────┐
│       Telegram Cloud        │
│   User's Saved Messages     │
│  (actual file storage)      │
└─────────────────────────────┘
```

- **Single persistent event loop** — a background thread runs one `asyncio` loop for all Telegram I/O to avoid the "Event loop is closed" error.
- **Client pool** — `TelegramClient` instances are cached per phone number and reused across requests.
- **In-memory metadata cache** — file listings are cached for 5 minutes per user to reduce Telegram API calls.
- **Fernet encryption** — `api_sessions.json`, `user_folders.json`, and `share_links.json` are encrypted at rest with the `SECRET_KEY`.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask 2.3 |
| Telegram Client | Telethon 1.32 (MTProto) |
| Encryption | `cryptography` (Fernet / AES-128-CBC) |
| Frontend | Vanilla HTML, CSS, JavaScript |
| Fonts | Google Fonts – Inter, Material Symbols Rounded |
| Session | Server-side token stored in HttpOnly cookie |

---

## 📂 Project Structure

```
telecloud/
├── main.py               # Flask app — all routes, session management, Telegram logic
├── security.py           # Rate limiting, input validation, phone validation, security logging
│
├── login.html            # OTP + 2FA login flow (3 steps)
├── upload.html           # Main dashboard — file browser, folder manager, uploader
├── setup.html            # First-time Telegram API credentials setup
├── consent.html          # Landing / consent page (entry point)
├── privacy_policy.html   # Privacy policy page
├── share.html            # Public sharing guest landing / folder preview page
│
├── static/
│   └── style.css         # Global dark-mode design system (glassmorphism)
│
├── sessions/             # Per-user Telethon .session files (gitignored)
├── uploads/              # Temporary staging directory (cleared after upload)
├── thumbs/               # Cached image/video thumbnails
│
├── user_folders.json     # Fernet-encrypted folder metadata per user
├── api_sessions.json     # Fernet-encrypted Telegram API credentials per session
├── share_links.json      # Fernet-encrypted share links metadata per user
├── app.log               # Application & security event log
│
├── .env                  # SECRET_KEY and optional API_ID/API_HASH
├── .gitignore
└── requirements.txt
```

---

## 🚀 Getting Started

### Prerequisites

- Python **3.9+**
- A **Telegram account** (to log in)
- Telegram **API ID** and **API Hash** — obtained for free from [my.telegram.org](https://my.telegram.org)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/sumanth2354/telecloud.git
cd telecloud

# 2. Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root (or copy from the template):

```env
# Required — generate a valid Fernet key with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
SECRET_KEY=your_fernet_key_here

# Optional — set server-wide Telegram credentials (users can also supply their own via /setup)
API_ID=12345678
API_HASH=your_api_hash_here

# Optional
SECURE_COOKIES=false          # Set to true when behind HTTPS
MAX_SCAN_MESSAGES=2000        # How many Telegram messages to scan for files (0 = unlimited)
API_SESSION_TTL=604800        # Per-user API credential TTL in seconds (default: 7 days)
```

> **Generating a SECRET_KEY:**
> ```bash
> python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
> ```

### Running the App

```bash
python main.py
```

The server starts at **http://127.0.0.1:5001**.

---

## 🧭 Usage

### First-time setup

1. Open **http://127.0.0.1:5001** in your browser — you'll see the consent/landing page.
2. Navigate to **http://127.0.0.1:5001/setup**.
3. Enter your **Telegram API ID** and **API Hash** (get them from [my.telegram.org](https://my.telegram.org)).
4. Click **Verify & Continue** — your credentials are encrypted and stored server-side for 7 days.

### Logging in

1. Go to `/login`.
2. Enter your phone number with country code (e.g. `+91XXXXXXXXXX`).
3. Telegram will send an OTP to your Telegram app — enter it.
4. If you have **Two-Step Verification (2FA)** enabled, enter your cloud password.
5. You'll be redirected to the main dashboard.

### Managing files

| Action | How |
|---|---|
| **Upload** | Drag files onto the upload zone or click to browse. Optionally select a folder. |
| **Create folder** | Click "+ New Folder" in the sidebar. |
| **Browse folder** | Click any folder in the sidebar to filter files. |
| **Search** | Use the search bar to find files by name. |
| **Filter by type** | Use the category tabs (Images, Videos, Audio, Documents…). |
| **Download** | Click the download icon on any file card. |
| **Delete** | Select files and click Delete. |
| **Move** | Select files, then choose "Move to Folder". |
| **Rename folder** | Right-click or use the folder options menu. |
| **Share folder** | Click the share icon on any folder card, configure options, and copy the link. |
| **Manage shared links** | Toggle the "My Shared Links" section in the dashboard to view, edit, or delete active links. |

---

## 📡 API Reference

All mutating endpoints require:
- A valid `session_token` HttpOnly cookie (set on login).
- The `X-CSRF-Token` request header matching the `csrf_token` cookie.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/` | ❌ | Consent / landing page |
| `GET` | `/setup` | ❌ | API credentials setup page |
| `POST` | `/setup-api` | ❌ | Save Telegram API credentials |
| `GET` | `/login` | ❌ | Login page |
| `POST` | `/send_code` | ❌ | Send OTP to phone via Telegram |
| `POST` | `/verify_code` | ❌ | Verify OTP, create session |
| `POST` | `/verify_password` | ❌ | Verify 2FA password, create session |
| `GET` | `/me` | ✅ | Return logged-in phone number |
| `GET` | `/upload-page` | ✅ | Main dashboard (HTML) |
| `POST` | `/upload` | ✅ | Upload files to Telegram |
| `POST` | `/list_folders` | ✅ | List user's virtual folders |
| `POST` | `/create_folder` | ✅ | Create a new folder |
| `POST` | `/list_files_in_folder` | ✅ | List files tagged with a folder name |
| `POST` | `/list_all_files` | ✅ | Paginated list of all files (with category filter) |
| `POST` | `/search_files` | ✅ | Search files by name |
| `POST` | `/move_files_to_folder` | ✅ | Reassign files to a folder |
| `POST` | `/delete_files` | ✅ | Delete files from Telegram |
| `POST` | `/rename_folder` | ✅ | Rename a folder and update all file captions |
| `POST` | `/delete_folder` | ✅ | Remove folder label (files remain in Telegram) |
| `POST` | `/folder_counts` | ✅ | File counts per folder + total storage |
| `GET` | `/get_file/<msg_id>` | ✅ | Stream/download file by Telegram message ID |
| `GET` | `/get_thumbnail/<msg_id>` | ✅ | Serve cached thumbnail for a file |
| `POST` | `/logout` | ❌ | Destroy session + purge API credentials |
| `POST` | `/delete_data` | ✅ | Delete all local data for the user |
| `GET` | `/privacy-policy` | ❌ | Privacy policy page |
| `POST` | `/share/create` | ✅ | Create a share link for a folder or all files |
| `GET` | `/share/list` | ✅ | List user's active share links |
| `POST` | `/share/update/<token>` | ✅ | Update label, active state, password, expiry of a link |
| `POST` | `/share/delete/<token>` | ✅ | Delete a share link |
| `GET` | `/share/<token>` | ❌ | Guest page for shared folder/files |
| `POST` | `/share/auth/<token>` | ❌ | Authenticate password-protected link |
| `POST` | `/share/files/<token>` | ❌ | List files in a shared folder for guest |
| `GET` | `/share/file/<token>/<msg_id>` | ❌ | Download/stream a file in a shared folder |
| `GET` | `/share/thumb/<token>/<msg_id>` | ❌ | Get cached thumbnail in a shared folder |

---

## 🔐 Security

TeleCloud is built with security in mind:

- **No file retention** — uploaded files are staged in `uploads/` only during transmission, then immediately deleted from disk.
- **Fernet encryption at rest** — `api_sessions.json` (Telegram API credentials), `user_folders.json` (folder metadata), and `share_links.json` (share links configuration) are AES-encrypted using a `SECRET_KEY`.
- **Password-protected sharing** — Guest links can be password-protected; passwords are salted and hashed using PBKDF2-HMAC-SHA256 (100,000 iterations). A signed session cookie (`share_session_<token>`) handles session verification.
- **Link expiration** — Shared links support optional expiration timestamps, preventing access once the set date and time pass.
- **Cascading deletion** — Logging out or deleting all account data automatically deletes all associated shared links.
- **HttpOnly session cookies** — session tokens are never accessible to JavaScript.
- **CSRF protection** — every `POST/PUT/DELETE` request is validated via the double-submit cookie pattern.
- **Rate limiting** — each IP is limited to 10 requests/minute and 100 requests/hour.
- **Phone number validation** — strict E.164 format enforced before any Telegram API call.
- **Input sanitisation** — all user-supplied strings are stripped of dangerous characters.
- **Session expiry** — server-side sessions expire after 1 hour of inactivity.
- **Phone hashing** — session files on disk are named with the SHA-256 hash of the phone number.
- **Security event logging** — all significant events (login, upload, delete, logout) are written to `app.log`.

> ⚠️ **Important:** Never commit your `.env` file. The `SECRET_KEY` is already listed in `.gitignore`.

---

## 🌍 Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `SECRET_KEY` | ✅ | — | Fernet key for encrypting stored data |
| `API_ID` | ❌ | — | Server-wide Telegram API ID (users can override via `/setup`) |
| `API_HASH` | ❌ | — | Server-wide Telegram API Hash |
| `SECURE_COOKIES` | ❌ | `false` | Set `true` to send cookies over HTTPS only |
| `MAX_SCAN_MESSAGES` | ❌ | `2000` | Maximum Telegram messages to scan (`0` = unlimited) |
| `API_SESSION_TTL` | ❌ | `604800` | Per-user API credential lifetime in seconds (7 days) |

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome!

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push and open a Pull Request.

Please make sure:
- Code follows the existing style.
- New endpoints include proper `@rate_limit` and `@require_auth` decorators where appropriate.
- Sensitive data is never logged in plain text.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

> Built with ❤️ using [Flask](https://flask.palletsprojects.com/) + [Telethon](https://docs.telethon.dev/) — your files, your Telegram, your cloud.

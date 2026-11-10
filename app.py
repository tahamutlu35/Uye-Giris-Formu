"""Small standard-library login server for the member form."""
from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import html
import re
import secrets
import sqlite3
import time
import os
import json
import smtplib
import ssl
import socket
from email.message import EmailMessage
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

BASE_DIR = Path(__file__).resolve().parent


def load_local_environment() -> None:
    try:
        lines = (BASE_DIR / ".env").read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if value.startswith(("'", '"')) and value.endswith(value[0]):
            value = value[1:-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            os.environ.setdefault(name, value)


load_local_environment()
DB_PATH = Path(os.environ.get("MEMBERS_DB_PATH", str(BASE_DIR / "members.db")))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "80"))
ITERATIONS = 310_000
MAX_PASSWORD_BYTES = 1024
CSRF_TOKEN_TTL = 60 * 60 * 2
LOGIN_ATTEMPT_LIMIT = 8
LOGIN_IP_ATTEMPT_LIMIT = 40
LOGIN_ATTEMPT_WINDOW = 60 * 15
_csrf_secret = os.environ.get("CSRF_SECRET", "")
if _csrf_secret and len(_csrf_secret.encode("utf-8")) < 32:
    raise RuntimeError("CSRF_SECRET en az 32 bayt olmalıdır.")
CSRF_SECRET = _csrf_secret.encode("utf-8") if _csrf_secret else secrets.token_bytes(32)
DUMMY_SALT = b"\x00" * 16
DUMMY_PASSWORD_HASH = hashlib.pbkdf2_hmac("sha256", b"not-a-real-password", DUMMY_SALT, ITERATIONS).hex()
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
SITE_URL = os.environ.get("SITE_URL", "http://kavrix.uyelik").rstrip("/")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", f"{SITE_URL}/auth/google/callback")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)


def connect_db() -> sqlite3.Connection:
    class ClosingConnection(sqlite3.Connection):
        def __exit__(self, exc_type, exc_value, traceback):
            try:
                return super().__exit__(exc_type, exc_value, traceback)
            finally:
                self.close()

    connection = sqlite3.connect(DB_PATH, factory=ClosingConnection)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS members ("
        "email TEXT PRIMARY KEY, password_hash TEXT NOT NULL, salt BLOB NOT NULL)"
    )
    columns = {row[1] for row in connection.execute("PRAGMA table_info(members)")}
    if "gender" not in columns:
        connection.execute("ALTER TABLE members ADD COLUMN gender TEXT NOT NULL DEFAULT 'unspecified'")
    if "profile_image" not in columns:
        connection.execute("ALTER TABLE members ADD COLUMN profile_image TEXT NOT NULL DEFAULT ''")
    if "full_name" not in columns:
        connection.execute("ALTER TABLE members ADD COLUMN full_name TEXT NOT NULL DEFAULT ''")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        "token_hash TEXT PRIMARY KEY, email TEXT NOT NULL REFERENCES members(email), "
        "expires_at INTEGER NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS password_resets ("
        "token_hash TEXT PRIMARY KEY, email TEXT NOT NULL REFERENCES members(email), expires_at INTEGER NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS login_attempts ("
        "key_hash TEXT PRIMARY KEY, window_started INTEGER NOT NULL, attempts INTEGER NOT NULL)"
    )
    return connection


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)


def csrf_token() -> str:
    issued_at = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    message = f"{issued_at}.{nonce}"
    signature = hmac.new(CSRF_SECRET, message.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{message}.{signature}"


def valid_csrf_token(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 256:
        return False
    try:
        issued_at, nonce, signature = value.split(".")
        timestamp = int(issued_at)
    except (ValueError, TypeError):
        return False
    now = int(time.time())
    if timestamp > now + 60 or now - timestamp > CSRF_TOKEN_TTL:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", nonce) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        return False
    message = f"{issued_at}.{nonce}"
    expected = hmac.new(CSRF_SECRET, message.encode("ascii"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def create_user() -> None:
    email = input("Üye e-posta adresi: ").strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise SystemExit("Geçerli bir e-posta adresi girin.")
    password = getpass.getpass("Şifre (en az 8 karakter): ")
    confirmation = getpass.getpass("Şifreyi tekrar girin: ")
    if len(password) < 8:
        raise SystemExit("Şifre en az 8 karakter olmalı.")
    if password != confirmation:
        raise SystemExit("Şifreler eşleşmiyor.")

    import secrets
    salt = secrets.token_bytes(16)
    digest = password_digest(password, salt)
    try:
        with connect_db() as db:
            db.execute(
                "INSERT INTO members (email, password_hash, salt) VALUES (?, ?, ?)",
                (email, digest.hex(), salt),
            )
    except sqlite3.IntegrityError:
        raise SystemExit("Bu e-posta adresi zaten kayıtlı.")
    print(f"Üye hesabı oluşturuldu: {email}")


class LoginHandler(BaseHTTPRequestHandler):
    def _session_token(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie["member_session"].value
        except Exception:
            return None
        return token if len(token) <= 128 and re.fullmatch(r"[A-Za-z0-9_-]+", token) else None

    def start_session(self, email: str) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with connect_db() as db:
            old_token = self._session_token()
            if old_token:
                db.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(old_token.encode("ascii")).hexdigest(),))
            db.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
            db.execute(
                "INSERT INTO sessions (token_hash, email, expires_at) VALUES (?, ?, ?)",
                (token_hash, email, int(time.time()) + 60 * 60 * 24 * 30),
            )
        return token

    def current_member(self) -> str | None:
        token = self._session_token()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        with connect_db() as db:
            row = db.execute(
                "SELECT email FROM sessions WHERE token_hash = ? AND expires_at >= ?",
                (token_hash, int(time.time())),
            ).fetchone()
        return row[0] if row else None

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def send_security_headers(self) -> None:
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if SITE_URL.startswith("https://"):
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        self.end_headers()

    def redirect_with_cookie(self, location: str, cookie: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        self.end_headers()

    @staticmethod
    def secure_cookie_attribute() -> str:
        return "; Secure" if SITE_URL.startswith("https://") else ""

    def redirect_with_session(self, location: str, token: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        secure = self.secure_cookie_attribute()
        self.send_header("Set-Cookie", f"member_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{secure}")
        self.send_header("Set-Cookie", f"google_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
        self.send_header("Cache-Control", "no-store")
        self.send_security_headers()
        self.end_headers()

    def render_page(self, filename: str) -> bytes:
        page = (BASE_DIR / filename).read_text(encoding="utf-8")
        page = page.replace("{{CSRF_TOKEN}}", html.escape(csrf_token(), quote=True))
        return page.encode("utf-8")

    def login_attempt_keys(self, email: str) -> tuple[str, str]:
        remote_ip = self.client_address[0] if self.client_address else "unknown"
        email_key = hmac.new(CSRF_SECRET, f"email\0{email}".encode("utf-8"), hashlib.sha256).hexdigest()
        ip_key = hmac.new(CSRF_SECRET, f"ip\0{remote_ip}".encode("utf-8"), hashlib.sha256).hexdigest()
        return email_key, ip_key

    def allow_login_attempt(self, email: str) -> bool:
        email_key, ip_key = self.login_attempt_keys(email)
        now = int(time.time())
        with connect_db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM login_attempts WHERE window_started < ?", (now - LOGIN_ATTEMPT_WINDOW,))
            rows = {row[0]: row[1] for row in db.execute(
                "SELECT key_hash, attempts FROM login_attempts WHERE key_hash IN (?, ?)",
                (email_key, ip_key),
            )}
            if rows.get(email_key, 0) >= LOGIN_ATTEMPT_LIMIT or rows.get(ip_key, 0) >= LOGIN_IP_ATTEMPT_LIMIT:
                return False
            for key in (email_key, ip_key):
                db.execute(
                    "INSERT INTO login_attempts (key_hash, window_started, attempts) VALUES (?, ?, 1) "
                    "ON CONFLICT(key_hash) DO UPDATE SET attempts = attempts + 1",
                    (key, now),
                )
        return True

    def clear_login_attempts(self, email: str) -> None:
        with connect_db() as db:
            email_key, ip_key = self.login_attempt_keys(email)
            db.execute("DELETE FROM login_attempts WHERE key_hash IN (?, ?)", (email_key, ip_key))

    def send_reset_email(self, email: str, token: str) -> None:
        if not SMTP_HOST or not SMTP_FROM:
            raise RuntimeError("SMTP_HOST ve SMTP_FROM ayarlanmamış.")
        link = f"{SITE_URL}/reset-password?token={urllib.parse.quote(token)}"
        message = EmailMessage()
        message["From"] = SMTP_FROM
        message["To"] = email
        message["Subject"] = "Parolanızı sıfırlayın"
        message.set_content(
            f"Parolanızı yenilemek için şu bağlantıyı açın (30 dakika geçerlidir):\n{link}\n\n"
            "Bu isteği siz yapmadıysanız bu e-postayı yok sayabilirsiniz."
        )
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.starttls(context=context)
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(message)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/forgot-password":
            self.send_bytes(200, self.render_page("index.html"), "text/html; charset=utf-8")
            return
        if path == "/reset-password":
            self.send_bytes(200, self.render_page("index.html"), "text/html; charset=utf-8")
            return
        if path == "/auth/google":
            if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
                self.redirect("/login?error=google_not_configured")
                return
            state = secrets.token_urlsafe(32)
            params = urllib.parse.urlencode({
                "client_id": GOOGLE_CLIENT_ID,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "response_type": "code",
                "scope": "openid email profile",
                "state": state,
                "prompt": "select_account",
            })
            self.redirect_with_cookie(
                "https://accounts.google.com/o/oauth2/v2/auth?" + params,
                f"google_oauth_state={state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600" + self.secure_cookie_attribute(),
            )
            return
        if path == "/auth/google/callback":
            query = parse_qs(urlsplit(self.path).query)
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            saved_state = cookie.get("google_oauth_state")
            state = query.get("state", [""])[0]
            if not saved_state or not state or not hmac.compare_digest(saved_state.value, state):
                self.redirect_with_cookie("/login?error=google_state", f"google_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{self.secure_cookie_attribute()}")
                return
            if query.get("error") or not query.get("code"):
                self.redirect_with_cookie("/login?error=google_cancelled", f"google_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{self.secure_cookie_attribute()}")
                return
            try:
                token_data = urllib.parse.urlencode({
                    "code": query["code"][0],
                    "client_id": GOOGLE_CLIENT_ID,
                    "client_secret": GOOGLE_CLIENT_SECRET,
                    "redirect_uri": GOOGLE_REDIRECT_URI,
                    "grant_type": "authorization_code",
                }).encode("utf-8")
                token_request = urllib.request.Request(
                    "https://oauth2.googleapis.com/token", data=token_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                with urllib.request.urlopen(token_request, timeout=10) as response:
                    access_token = json.load(response)["access_token"]
                profile_request = urllib.request.Request(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                with urllib.request.urlopen(profile_request, timeout=10) as response:
                    profile = json.load(response)
                email = profile.get("email", "").strip().lower()
                if not profile.get("verified_email") or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                    raise ValueError("Google hesabının doğrulanmış e-posta adresi alınamadı.")
                with connect_db() as db:
                    exists = db.execute("SELECT 1 FROM members WHERE email = ?", (email,)).fetchone()
                    if not exists:
                        salt = secrets.token_bytes(16)
                        random_password = secrets.token_urlsafe(48)
                        db.execute(
                            "INSERT INTO members (email, password_hash, salt, full_name) VALUES (?, ?, ?, ?)",
                            (email, password_digest(random_password, salt).hex(), salt, profile.get("name", "").strip()[:120]),
                        )
                token = self.start_session(email)
                self.redirect_with_session("/dashboard", token)
            except (urllib.error.URLError, urllib.error.HTTPError, KeyError, ValueError, json.JSONDecodeError) as exc:
                print(f"Google OAuth error: {exc}")
                self.redirect_with_cookie("/login?error=google_failed", f"google_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{self.secure_cookie_attribute()}")
            return
        if path in ("/welcome", "/dashboard"):
            email = self.current_member()
            if not email:
                self.redirect("/login")
                return
            if path == "/welcome":
                self.redirect("/dashboard")
                return
            with connect_db() as db:
                row = db.execute("SELECT gender, profile_image, full_name FROM members WHERE email = ?", (email,)).fetchone()
            page = self.render_page("index.html").decode("utf-8")
            page = page.replace("{{EMAIL}}", html.escape(email, quote=True))
            page = page.replace("{{NAME}}", html.escape((row[2] if row and row[2] else email.split("@")[0]), quote=True))
            page = page.replace("{{GENDER}}", html.escape(row[0] if row else "unspecified", quote=True))
            page = page.replace("{{PROFILE_IMAGE}}", html.escape(row[1] if row else "", quote=True))
            page = page.encode("utf-8")
            """(
                '<!doctype html><html lang="tr"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                '<title>Üye Alanı</title><style>body{font:16px Arial,sans-serif;background:#f3f2fa;min-height:100vh;display:grid;place-items:center;margin:0}.card{background:white;padding:48px;border-radius:18px;box-shadow:0 15px 50px #25243f22;text-align:center}button{padding:12px 22px;border:0;border-radius:8px;background:#7865f6;color:white;cursor:pointer}</style>'
                f"</head><body><main class='card'><h1>Hoş geldin!</h1><p>{html.escape(email)} hesabıyla giriş yaptın.</p><form method='post' action='/logout'><button>Çıkış yap</button></form></main></body></html>"
            ).encode("utf-8")"""
            self.send_bytes(200, page, "text/html; charset=utf-8")
            return
        if path in ("/register", "/register.html"):
            self.redirect("/")
            return
        if path == "/":
            target = BASE_DIR / "register.html"
            content_type = "text/html; charset=utf-8"
        elif path == "/login":
            target = BASE_DIR / "index.html"
            content_type = "text/html; charset=utf-8"
        elif path == "/style.css":
            target = BASE_DIR / "style.css"
            content_type = "text/css; charset=utf-8"
        elif path == "/corporate.css":
            target = BASE_DIR / "corporate.css"
            content_type = "text/css; charset=utf-8"
        elif path == "/corporate.js":
            target = BASE_DIR / "corporate.js"
            content_type = "application/javascript; charset=utf-8"
        else:
            self.send_error(404)
            return
        try:
            content = self.render_page(target.name) if content_type.startswith("text/html") else target.read_bytes()
            self.send_bytes(200, content, content_type)
        except OSError:
            self.send_error(500, "Gerekli sayfa dosyası bulunamadı.")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/profile":
            email = self.current_member()
            if not email:
                self.send_bytes(401, b'{"error":"Oturum sona erdi."}', "application/json; charset=utf-8")
                return
            if not valid_csrf_token(self.headers.get("X-CSRF-Token", "")):
                self.send_bytes(403, b'{"error":"CSRF validation failed."}', "application/json; charset=utf-8")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if length < 0 or length > 2_800_000:
                self.send_error(413)
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                gender, image = payload.get("gender", "unspecified"), payload.get("profile_image", "")
                if gender not in ("woman", "man", "unspecified"):
                    raise ValueError("Geçersiz profil seçimi.")
                if image and (not isinstance(image, str) or not re.fullmatch(r"data:image/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}", image) or len(image) > 2_700_000):
                    raise ValueError("Fotoğraf PNG, JPG veya WebP olmalı ve 2 MB'tan küçük olmalı.")
                with connect_db() as db:
                    db.execute("UPDATE members SET gender = ?, profile_image = ? WHERE email = ?", (gender, image, email))
                self.send_bytes(200, b'{"ok":true}', "application/json; charset=utf-8")
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                self.send_bytes(400, json.dumps({"error": str(exc)}, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")
            return
        if path not in ("/login", "/register", "/logout", "/forgot-password", "/reset-password"):
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > 16_384:
            self.send_error(413)
            return
        try:
            form = parse_qs(self.rfile.read(length).decode("utf-8", errors="strict"), max_num_fields=32)
        except (UnicodeDecodeError, ValueError):
            self.send_error(400)
            return
        if not valid_csrf_token(form.get("csrf_token", [""])[0]):
            self.send_error(403, "CSRF validation failed")
            return
        if path == "/logout":
            token = self._session_token()
            if token:
                token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
                with connect_db() as db:
                    db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            self.send_response(303)
            self.send_header("Location", "/login")
            secure = self.secure_cookie_attribute()
            self.send_header("Set-Cookie", f"member_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
            self.send_security_headers()
            self.end_headers()
            return
        if path == "/forgot-password":
            email = form.get("email", [""])[0].strip().lower()
            if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                with connect_db() as db:
                    exists = db.execute("SELECT 1 FROM members WHERE email = ?", (email,)).fetchone()
                    if exists:
                        token = secrets.token_urlsafe(32)
                        db.execute("DELETE FROM password_resets WHERE email = ?", (email,))
                        db.execute("INSERT INTO password_resets VALUES (?, ?, ?)",
                                   (hashlib.sha256(token.encode()).hexdigest(), email, int(time.time()) + 1800))
                if exists:
                    try:
                        self.send_reset_email(email, token)
                    except (OSError, smtplib.SMTPException, RuntimeError, socket.timeout) as exc:
                        print(f"Password reset email error: {exc}")
                        # Keep the public response identical for known and unknown accounts.
            self.redirect("/forgot-password?sent=1")
            return
        if path == "/reset-password":
            token = form.get("token", [""])[0]
            password = form.get("password", [""])[0]
            confirmation = form.get("password_confirmation", [""])[0]
            if len(password) < 8 or len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
                self.redirect("/reset-password?error=password&token=" + urllib.parse.quote(token))
                return
            if password != confirmation:
                self.redirect("/reset-password?error=confirm&token=" + urllib.parse.quote(token))
                return
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            with connect_db() as db:
                row = db.execute("SELECT email FROM password_resets WHERE token_hash = ? AND expires_at >= ?",
                                 (token_hash, int(time.time()))).fetchone()
                if not row:
                    self.redirect("/reset-password?error=expired")
                    return
                salt = secrets.token_bytes(16)
                db.execute("UPDATE members SET password_hash = ?, salt = ? WHERE email = ?",
                           (password_digest(password, salt).hex(), salt, row[0]))
                db.execute("DELETE FROM password_resets WHERE email = ?", (row[0],))
                db.execute("DELETE FROM sessions WHERE email = ?", (row[0],))
            self.redirect("/login?notice=password_reset")
            return
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        if path == "/register":
            full_name = " ".join(form.get("full_name", [""])[0].split())
            confirmation = form.get("password_confirmation", [""])[0]
            if not full_name or len(full_name) > 120:
                self.redirect("/?error=name")
                return
            if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                self.redirect("/?error=email")
                return
            if len(password) < 8 or len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
                self.redirect("/?error=password")
                return
            if password != confirmation:
                self.redirect("/?error=confirm")
                return
            salt = secrets.token_bytes(16)
            digest = password_digest(password, salt).hex()
            try:
                with connect_db() as db:
                    db.execute(
                        "INSERT INTO members (email, password_hash, salt, full_name) VALUES (?, ?, ?, ?)",
                        (email, digest, salt, full_name),
                    )
            except sqlite3.IntegrityError:
                self.redirect("/?error=register")
                return
            self.redirect("/login?notice=registered")
            return
        if not self.allow_login_attempt(email if len(email) <= 254 else "__invalid_email__"):
            self.redirect("/login?error=invalid")
            return
        valid = False
        row = None
        if len(email) <= 254:
            with connect_db() as db:
                row = db.execute(
                    "SELECT password_hash, salt FROM members WHERE email = ?", (email,)
                ).fetchone()
        too_long = len(password.encode("utf-8")) > MAX_PASSWORD_BYTES
        hash_input = password if not too_long else "invalid-password-length"
        expected_hash, salt = row if row else (DUMMY_PASSWORD_HASH, DUMMY_SALT)
        actual_hash = password_digest(hash_input, salt)
        valid = bool(row) and not too_long and hmac.compare_digest(actual_hash.hex(), expected_hash)
        if valid:
            self.clear_login_attempts(email)
            self.redirect_with_session("/dashboard", self.start_session(email))
        else:
            self.redirect("/login?error=invalid")

    def log_message(self, format: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Üye giriş formu sunucusu")
    parser.add_argument("command", nargs="?", choices=("serve", "create-user"), default="serve")
    args = parser.parse_args()
    if args.command == "create-user":
        create_user()
        return
    connect_db().close()
    try:
        server = ThreadingHTTPServer((HOST, PORT), LoginHandler)
    except OSError as exc:
        if PORT == 80 and (getattr(exc, "winerror", None) in (10013, 10048) or exc.errno in (13, 98, 10048)):
            print(f"Could not bind 127.0.0.1:80: {exc}")
            print("Port 80 may be occupied by another application or require elevated permissions.")
            print("Alternative: PowerShell: $env:PORT=8080; $env:SITE_URL=http://kavrix.uyelik:8080; python app.py")
            return
        raise
    print(f"Membership app at {SITE_URL}")
    print("Sunucuyu durdurmak için Ctrl+C kullanın.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSunucu kapatılıyor.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

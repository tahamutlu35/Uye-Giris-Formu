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
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "members.db"
HOST = "127.0.0.1"
PORT = 8000
ITERATIONS = 310_000
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", f"http://{HOST}:{PORT}/auth/google/callback")


def connect_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS members ("
        "email TEXT PRIMARY KEY, password_hash TEXT NOT NULL, salt BLOB NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS sessions ("
        "token_hash TEXT PRIMARY KEY, email TEXT NOT NULL REFERENCES members(email), "
        "expires_at INTEGER NOT NULL)"
    )
    return connection


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)


def create_user() -> None:
    email = input("Üye e-posta adresi: ").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
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
    def start_session(self, email: str) -> str:
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with connect_db() as db:
            db.execute("DELETE FROM sessions WHERE expires_at < ?", (int(time.time()),))
            db.execute(
                "INSERT INTO sessions (token_hash, email, expires_at) VALUES (?, ?, ?)",
                (token_hash, email, int(time.time()) + 60 * 60 * 24 * 30),
            )
        return token

    def current_member(self) -> str | None:
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie["member_session"].value
        except Exception:
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
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def redirect_with_cookie(self, location: str, cookie: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Set-Cookie", cookie)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def redirect_with_session(self, location: str, token: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Set-Cookie", f"member_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000")
        self.send_header("Set-Cookie", "google_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/auth/google":
            if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
                self.redirect("/?error=google_not_configured")
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
                f"google_oauth_state={state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600",
            )
            return
        if path == "/auth/google/callback":
            query = parse_qs(urlsplit(self.path).query)
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
            saved_state = cookie.get("google_oauth_state")
            state = query.get("state", [""])[0]
            if not saved_state or not state or not hmac.compare_digest(saved_state.value, state):
                self.redirect_with_cookie("/?error=google_state", "google_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
                return
            if query.get("error") or not query.get("code"):
                self.redirect_with_cookie("/?error=google_cancelled", "google_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
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
                            "INSERT INTO members (email, password_hash, salt) VALUES (?, ?, ?)",
                            (email, password_digest(random_password, salt).hex(), salt),
                        )
                token = self.start_session(email)
                self.redirect_with_session("/welcome", token)
            except (urllib.error.URLError, urllib.error.HTTPError, KeyError, ValueError, json.JSONDecodeError) as exc:
                print(f"Google OAuth error: {exc}")
                self.redirect_with_cookie("/?error=google_failed", "google_oauth_state=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            return
        if path == "/welcome":
            email = self.current_member()
            if not email:
                self.redirect("/")
                return
            page = (
                '<!doctype html><html lang="tr"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1">'
                '<title>Üye Alanı</title><style>body{font:16px Arial,sans-serif;background:#f3f2fa;min-height:100vh;display:grid;place-items:center;margin:0}.card{background:white;padding:48px;border-radius:18px;box-shadow:0 15px 50px #25243f22;text-align:center}button{padding:12px 22px;border:0;border-radius:8px;background:#7865f6;color:white;cursor:pointer}</style>'
                f"</head><body><main class='card'><h1>Hoş geldin!</h1><p>{html.escape(email)} hesabıyla giriş yaptın.</p><form method='post' action='/logout'><button>Çıkış yap</button></form></main></body></html>"
            ).encode("utf-8")
            self.send_bytes(200, page, "text/html; charset=utf-8")
            return
        if path == "/register":
            page = (BASE_DIR / "register.html").read_bytes()
            self.send_bytes(200, page, "text/html; charset=utf-8")
            return
        if path == "/":
            target = BASE_DIR / "index.html"
            content_type = "text/html; charset=utf-8"
        elif path == "/style.css":
            target = BASE_DIR / "style.css"
            content_type = "text/css; charset=utf-8"
        else:
            self.send_error(404)
            return
        try:
            self.send_bytes(200, target.read_bytes(), content_type)
        except OSError:
            self.send_error(500, "Gerekli sayfa dosyası bulunamadı.")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path not in ("/login", "/register", "/logout"):
            self.send_error(404)
            return
        length = min(max(int(self.headers.get("Content-Length", "0")), 0), 16_384)
        form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        if path == "/logout":
            member = self.current_member()
            if member:
                cookie = SimpleCookie()
                cookie.load(self.headers.get("Cookie", ""))
                token = cookie.get("member_session")
                if token:
                    token_hash = hashlib.sha256(token.value.encode("ascii", errors="ignore")).hexdigest()
                    with connect_db() as db:
                        db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "member_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            self.end_headers()
            return
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        if path == "/register":
            confirmation = form.get("password_confirmation", [""])[0]
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                self.redirect("/register?error=email")
                return
            if len(password) < 8:
                self.redirect("/register?error=password")
                return
            if password != confirmation:
                self.redirect("/register?error=confirm")
                return
            salt = secrets.token_bytes(16)
            digest = password_digest(password, salt).hex()
            try:
                with connect_db() as db:
                    db.execute(
                        "INSERT INTO members (email, password_hash, salt) VALUES (?, ?, ?)",
                        (email, digest, salt),
                    )
            except sqlite3.IntegrityError:
                self.redirect("/register?error=exists")
                return
            self.redirect_with_session("/welcome", self.start_session(email))
            return
        valid = False
        with connect_db() as db:
            row = db.execute(
                "SELECT password_hash, salt FROM members WHERE email = ?", (email,)
            ).fetchone()
        if row:
            expected_hash, salt = row
            actual_hash = password_digest(password, salt)
            valid = hmac.compare_digest(actual_hash.hex(), expected_hash)
        if valid:
            self.redirect_with_session("/welcome", self.start_session(email))
        else:
            self.redirect("/?error=invalid")

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
    server = ThreadingHTTPServer((HOST, PORT), LoginHandler)
    print(f"Giriş formu: http://{HOST}:{PORT}")
    print("Sunucuyu durdurmak için Ctrl+C kullanın.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nSunucu kapatılıyor.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

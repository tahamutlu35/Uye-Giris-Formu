import hashlib
import http.client
import re
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

import app


class MembershipSecurityTests(unittest.TestCase):
    def setUp(self):
        self.test_db = Path(__file__).parent / "security-test.db"
        self.db_path = app.DB_PATH
        self.site_url = app.SITE_URL
        app.DB_PATH = self.test_db
        app.SITE_URL = "https://test.example"
        app.connect_db().close()
        self.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.LoginHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        self.cookie = ""

    def tearDown(self):
        self.conn.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        app.DB_PATH = self.db_path
        app.SITE_URL = self.site_url
        for suffix in ("", "-journal", "-wal", "-shm"):
            candidate = Path(str(self.test_db) + suffix)
            if candidate.exists():
                candidate.unlink()

    def request(self, method, path, form=None, cookie=None, headers=None, raw_body=None):
        headers = dict(headers or {})
        if cookie:
            headers["Cookie"] = cookie
        body = raw_body if raw_body is not None else (urlencode(form or {}) if form is not None else None)
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.conn.request(method, path, body=body, headers=headers)
        response = self.conn.getresponse()
        data = response.read()
        result = dict(response.getheaders())
        cookies = response.headers.get_all("Set-Cookie") or []
        if cookies:
            result["Set-Cookie"] = cookies
        return response.status, result, data

    def token(self):
        status, _, body = self.request("GET", "/login")
        self.assertEqual(status, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', body)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def post(self, path, form, cookie=None):
        values = {**form, "csrf_token": self.token()}
        return self.request("POST", path, values, cookie)

    def register(self, email="person@example.com", password="correct horse battery"):
        return self.post("/register", {"full_name": "Test Person", "email": email,
                                        "password": password, "password_confirmation": password})

    def login(self, email="person@example.com", password="correct horse battery", cookie=None):
        return self.post("/login", {"email": email, "password": password}, cookie)

    def session_cookie(self, headers):
        return next((v.split(";", 1)[0] for v in headers.get("Set-Cookie", []) if v.startswith("member_session=")), repr(headers))

    def test_public_routes_csrf_and_registration(self):
        status, _, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Hesab", body)
        self.assertNotIn(b"{{CSRF_TOKEN}}", body)
        self.assertEqual(self.request("POST", "/profile", {})[0], 401)
        self.assertEqual(self.request("GET", "/dashboard")[1]["Location"], "/login")
        status, _, _ = self.request("POST", "/register", {"email": "x@y.z"})
        self.assertEqual(status, 403)
        self.assertEqual(self.register()[0], 303)
        self.assertEqual(self.register()[0], 303)
        with app.connect_db() as db:
            rows = db.execute("SELECT password_hash, salt FROM members WHERE email=?", ("person@example.com",)).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertRegex(rows[0][0], r"^[0-9a-f]{64}$")
        self.assertEqual(len(rows[0][1]), 16)

    def test_generic_bad_login_and_throttling(self):
        self.register()
        self.assertEqual(self.login(password="incorrect password")[1]["Location"], "/login?error=invalid")
        self.assertEqual(self.login(email="missing@example.com", password="incorrect password")[1]["Location"], "/login?error=invalid")
        for _ in range(app.LOGIN_ATTEMPT_LIMIT - 1):
            self.login(password="incorrect password")
        self.assertEqual(self.login()[1]["Location"], "/login?error=invalid")
        with app.connect_db() as db:
            count = db.execute("SELECT attempts FROM login_attempts").fetchone()[0]
        self.assertEqual(count, app.LOGIN_ATTEMPT_LIMIT)

    def test_secure_session_rotation_logout_and_per_request_auth(self):
        self.register()
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        cookie1 = self.session_cookie(headers)
        set_cookie = next(v for v in headers["Set-Cookie"] if v.startswith("member_session="))
        self.assertIn("Secure", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Lax", set_cookie)
        self.assertEqual(self.request("GET", "/dashboard", cookie=cookie1)[0], 200)
        profile_headers = {"Content-Type": "application/json"}
        status, _, _ = self.request("POST", "/profile", cookie=cookie1, headers=profile_headers, raw_body=b"{}")
        self.assertEqual(status, 403)
        profile_headers["X-CSRF-Token"] = self.token()
        status, _, payload = self.request("POST", "/profile", cookie=cookie1, headers=profile_headers, raw_body=b"{}")
        self.assertEqual(status, 200)
        self.assertIn(b'"ok":true', payload)
        status, headers, _ = self.login(cookie=cookie1)
        cookie2 = self.session_cookie(headers)
        self.assertEqual(self.request("GET", "/dashboard", cookie=cookie1)[1]["Location"], "/login")
        self.assertEqual(self.request("GET", "/dashboard", cookie=cookie2)[0], 200)
        with app.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sessions WHERE token_hash=?",
                                        (hashlib.sha256(cookie2.split("=", 1)[1].encode()).hexdigest(),)).fetchone()[0], 1)
        self.assertEqual(self.post("/logout", {}, cookie=cookie2)[0], 303)
        self.assertEqual(self.request("GET", "/dashboard", cookie=cookie2)[1]["Location"], "/login")
        with app.connect_db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)

    def test_password_reset_token_is_one_use_and_revokes_sessions(self):
        self.register()
        _, headers, _ = self.login()
        cookie = self.session_cookie(headers)
        import secrets, time
        raw_token = secrets.token_urlsafe(32)
        with app.connect_db() as db:
            db.execute("INSERT INTO password_resets VALUES (?, ?, ?)",
                       (hashlib.sha256(raw_token.encode()).hexdigest(), "person@example.com", int(time.time()) + 1800))
        form = {"token": raw_token, "password": "new secure password", "password_confirmation": "new secure password"}
        self.assertEqual(self.post("/reset-password", form)[0], 303)
        self.assertEqual(self.request("GET", "/dashboard", cookie=cookie)[1]["Location"], "/login")
        self.assertEqual(self.post("/reset-password", form)[1]["Location"], "/reset-password?error=expired")
        with app.connect_db() as db:
            row = db.execute("SELECT password_hash, salt FROM members WHERE email=?", ("person@example.com",)).fetchone()
        self.assertTrue(app.hmac.compare_digest(app.password_digest("new secure password", row[1]).hex(), row[0]))


if __name__ == "__main__":
    unittest.main()

import os
import re
import sqlite3
import secrets
import threading
import time
import socket
import random
from urllib.parse import urlparse, urljoin, urldefrag
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for, flash, session,
    jsonify, send_file, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, logout_user,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from bs4 import BeautifulSoup

# --- CONFIG ---
ADMIN_EMAIL = "terry@terryecom.com"
ADMIN_PASSWORD_HASH = generate_password_hash("Aph180912!!!")
APP_URL = os.environ.get("APP_URL", "https://yourapp.onrender.com")  # Set to your Render/custom domain

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', secrets.token_hex(24))
DATABASE = "users.db"

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# --- DB SETUP ---

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_verified INTEGER NOT NULL DEFAULT 0,
            verify_token TEXT,
            last_login TEXT,
            created_at TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS feature_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            message TEXT,
            submitted_at TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS crawl_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            domain TEXT,
            crawled_at TEXT
        )
        """)
        conn.commit()

# --- USER MODEL ---

class User(UserMixin):
    def __init__(self, id, email, password_hash, is_verified, verify_token, last_login, created_at):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.is_verified = is_verified
        self.verify_token = verify_token
        self.last_login = last_login
        self.created_at = created_at

    @staticmethod
    def get_by_email(email):
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email=?", (email,))
            row = cur.fetchone()
            if row:
                return User(*row)
            return None

    @staticmethod
    def get_by_id(id):
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE id=?", (id,))
            row = cur.fetchone()
            if row:
                return User(*row)
            return None

    @staticmethod
    def get_by_token(token):
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE verify_token=?", (token,))
            row = cur.fetchone()
            if row:
                return User(*row)
            return None

    def get_id(self):
        return str(self.id)

    def is_admin(self):
        return self.email.lower() == ADMIN_EMAIL.lower()

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "is_verified": self.is_verified,
            "last_login": self.last_login,
            "created_at": self.created_at
        }

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

# --- BREVO EMAIL ---

def send_email_brevo(to_email, subject, html_content, from_name="Terry Ecom Link Checker"):
    api_key = os.environ.get("BREVO_API_KEY")
    if not api_key:
        print("No BREVO_API_KEY found, cannot send email.")
        return False
    url = "https://api.brevo.com/v3/smtp/email"
    data = {
        "sender": {"name": from_name, "email": "terry@terryecom.com"},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": api_key
    }
    try:
        r = requests.post(url, json=data, headers=headers, timeout=12)
        if r.status_code not in (200, 201, 202):
            print("Failed to send email:", r.text)
        return r.status_code in (200, 201, 202)
    except Exception as e:
        print("Error sending email:", e)
        return False

# --- USER AUTH ROUTES ---

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"].strip()
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email address.", "danger")
            return render_template("signup.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("signup.html")
        if User.get_by_email(email):
            flash("Email already registered.", "danger")
            return render_template("signup.html")
        verify_token = secrets.token_urlsafe(24)
        password_hash = generate_password_hash(password)
        with sqlite3.connect(DATABASE) as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (email, password_hash, is_verified, verify_token, created_at) VALUES (?, ?, 0, ?, ?)",
                (email, password_hash, verify_token, datetime.utcnow().isoformat())
            )
            conn.commit()
        verify_url = f"{APP_URL}/verify/{verify_token}"
        html = f"""<h2>Welcome to Terry Ecom Link Checker!</h2>
            <p>Click to verify your email: <a href="{verify_url}">{verify_url}</a></p>
            <p>If you did not request this, ignore this email.</p>
        """
        send_email_brevo(email, "Verify your email", html)
        flash("Signup successful! Please check your email to verify your account.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if email == ADMIN_EMAIL and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        user = User.get_by_email(email)
        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash("Please verify your email first!", "warning")
                return render_template("login.html")
            login_user(user)
            # Update last_login
            with sqlite3.connect(DATABASE) as conn:
                conn.execute("UPDATE users SET last_login=? WHERE id=?", (datetime.utcnow().isoformat(), user.id))
            return redirect(url_for("index"))
        flash("Invalid login.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    logout_user()
    session.pop("admin", None)
    flash("Logged out.", "info")
    return redirect(url_for("login"))

@app.route("/verify/<token>")
def verify(token):
    user = User.get_by_token(token)
    if not user:
        flash("Invalid verification link.", "danger")
        return redirect(url_for("signup"))
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("UPDATE users SET is_verified=1, verify_token=NULL WHERE id=?", (user.id,))
    flash("Email verified! You can now login.", "success")
    return redirect(url_for("login"))

# --- ADMIN ---

@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if email == ADMIN_EMAIL and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin login.", "danger")
    return render_template("admin_login.html")

@app.route("/admin")
def admin_dashboard():
    if not session.get("admin"):
        abort(403)
    # Stats
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users")
        user_count = cur.fetchone()[0]
        cur.execute("SELECT email, is_verified, last_login, created_at FROM users")
        users = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM crawl_logs")
        crawl_count = cur.fetchone()[0]
        cur.execute("SELECT user_email, domain, crawled_at FROM crawl_logs ORDER BY crawled_at DESC LIMIT 25")
        crawl_logs = cur.fetchall()
        cur.execute("SELECT * FROM feature_reports ORDER BY submitted_at DESC LIMIT 25")
        feature_reports = cur.fetchall()
    return render_template("admin.html",
        user_count=user_count,
        users=users,
        crawl_count=crawl_count,
        crawl_logs=crawl_logs,
        feature_reports=feature_reports
    )

@app.route("/admin-logout")
def admin_logout():
    session.pop("admin", None)
    flash("Admin logged out.", "info")
    return redirect(url_for("admin_login"))

# --- FEATURE REQUEST / BUG REPORT ---

@app.route("/feature-report", methods=["POST"])
def feature_report():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    message = request.form.get("message", "").strip()
    if not message:
        return jsonify({"success": False, "msg": "Message is required."}), 400
    # Store in DB for admin stats
    with sqlite3.connect(DATABASE) as conn:
        conn.execute(
            "INSERT INTO feature_reports (name, email, message, submitted_at) VALUES (?, ?, ?, ?)",
            (name, email, message, datetime.utcnow().isoformat())
        )
    # Email to admin via Brevo
    subject = "New Feature Request / Bug Report"
    html = f"<h2>New Feature Request / Bug Report</h2><b>From:</b> {name or '(Anonymous)'}<br><b>Email:</b> {email or '(Not provided)'}<br><pre>{message}</pre>"
    send_email_brevo(ADMIN_EMAIL, subject, html)
    return jsonify({"success": True, "msg": "Thank you! Your message has been sent."})

# --- MAIN PAGE (CRAWL) ---

crawl_states = {}
EXCLUDED_DOMAINS = [
    'g.co', 'facebook.com', 'instagram.com', 'x.com', 'twitter.com',
    'pinterest.com', 'shopify.com', 'edpb.europa.eu'
]

def normalize_domain(domain):
    return domain.lower().replace("www.", "")

def crawl_site(start_url, domain, session_id, user_email):
    state = crawl_states[session_id]
    state["logs"].append(f"🌐 Starting crawl: {start_url}")
    visited = set()
    to_visit = [start_url]
    outbound_links = {}
    broken_links = {}
    pages_scanned = 0

    state["max_progress_seen"] = 0

    should_cancel = lambda: crawl_states.get(session_id, {}).get("cancel", False)

    while to_visit and not should_cancel():
        url = to_visit.pop(0)
        if url not in visited:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 404:
                    broken_links.setdefault(url, set()).add(url)
                    state["logs"].append(f"❌ 404 Not Found: {url} (found on {url})")
                    continue
                soup = BeautifulSoup(response.text, "html.parser")
                visited.add(url)
                state["logs"].append(f"✅ Scanned: {url}")

                for a in soup.find_all("a", href=True):
                    href = a['href'].strip()
                    if href == "#" or href.lower().startswith(("javascript:", "tel:")):
                        continue
                    if href.startswith("mailto:"):
                        try:
                            email = href.split(':',1)[1].split('?',1)[0]
                            email_domain = email.split('@')[1].lower()
                            if normalize_domain(email_domain) != domain:
                                already_seen = outbound_links.setdefault(href, set())
                                if url not in already_seen:
                                    already_seen.add(url)
                                    state["logs"].append(f"📧 External mailto: {href} (found on {url})")
                        except Exception:
                            already_seen = outbound_links.setdefault(href, set())
                            if url not in already_seen:
                                already_seen.add(url)
                                state["logs"].append(f"📧 Malformed mailto: {href} (found on {url})")
                        continue

                    raw_url = urldefrag(urljoin(url, href))[0]
                    parsed = urlparse(raw_url)
                    netloc = normalize_domain(parsed.netloc)
                    normalized_url = parsed._replace(netloc=netloc).geturl()

                    if netloc == "" or domain in netloc:
                        if normalized_url not in visited and normalized_url not in to_visit:
                            to_visit.append(normalized_url)
                    else:
                        if any(skip in netloc for skip in EXCLUDED_DOMAINS):
                            continue
                        outbound_links.setdefault(normalized_url, set()).add(url)
                        state["logs"].append(f"🔗 Outbound: {normalized_url} (found on {url})")
                        try:
                            ext_resp = requests.get(normalized_url, timeout=5)
                            if ext_resp.status_code == 404:
                                broken_links.setdefault(normalized_url, set()).add(url)
                                state["logs"].append(f"❌ 404 External: {normalized_url} (found on {url})")
                        except Exception:
                            broken_links.setdefault(normalized_url, set()).add(url)
                            state["logs"].append(f"❌ Failed to load: {normalized_url} (found on {url})")

                pages_scanned += 1
                progress = int((pages_scanned / (pages_scanned + len(to_visit))) * 100) if (pages_scanned + len(to_visit)) else 100
                state["max_progress_seen"] = max(state.get("max_progress_seen", 0), progress)
                state["progress"] = state["max_progress_seen"]
                state["pages_scanned"] = pages_scanned

            except Exception:
                broken_links.setdefault(url, set()).add(url)
                state["logs"].append(f"❌ Failed to crawl: {url} (found on {url})")

        state["visited"] = list(visited)
        state["outbound_links"] = {k: list(v) for k, v in outbound_links.items()}
        state["broken_links"] = {k: list(v) for k, v in broken_links.items()}

    state["logs"].append(f"✅ Crawl complete. Outbound links: {len(outbound_links)}, 404s: {len(broken_links)}")
    state["progress"] = 100
    state["finished"] = True

@app.route("/", methods=["GET"])
@login_required
def index():
    if not current_user.is_verified:
        flash("Please verify your email first!", "warning")
        return redirect(url_for("logout"))
    # Math captcha for anti-bot
    a, b = random.randint(1, 10), random.randint(1, 10)
    session["captcha_answer"] = a + b
    return render_template("index.html", captcha_a=a, captcha_b=b, user_email=current_user.email)

@app.route("/start_crawl", methods=["POST"])
@login_required
def start_crawl():
    if not current_user.is_verified:
        return jsonify({"status": "error", "msg": "❌ Verify your email to use the crawler!"}), 403
    user_captcha = request.form.get("captcha", "").strip()
    if "captcha_answer" not in session or not user_captcha.isdigit() or int(user_captcha) != session["captcha_answer"]:
        return jsonify({"status": "error", "msg": "❌ Captcha incorrect. Please try again."}), 400

    url = request.form.get("url", "").strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    parsed = urlparse(url)
    domain = normalize_domain(parsed.netloc if parsed.netloc else parsed.path)
    if not domain:
        return jsonify({"status": "error", "msg": "❌ Please enter a valid URL or domain."}), 400
    session_id = session.get("sid") or str(time.time()) + str(os.getpid())
    session["sid"] = session_id

    try:
        socket.gethostbyname(domain)
    except socket.error:
        return jsonify({"status": "error", "msg": "❌ Domain does not exist or is unreachable!"}), 400

    crawl_states[session_id] = {
        "logs": [],
        "progress": 0,
        "pages_scanned": 0,
        "visited": [],
        "outbound_links": {},
        "broken_links": {},
        "finished": False,
        "cancel": False,
        "start_url": url,
        "domain": domain,
        "max_progress_seen": 0
    }

    # Log crawl in DB for admin stats
    with sqlite3.connect(DATABASE) as conn:
        conn.execute(
            "INSERT INTO crawl_logs (user_email, domain, crawled_at) VALUES (?, ?, ?)",
            (current_user.email, domain, datetime.utcnow().isoformat())
        )

    threading.Thread(target=crawl_site, args=(url, domain, session_id, current_user.email), daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/progress", methods=["GET"])
@login_required
def progress():
    session_id = session.get("sid")
    state = crawl_states.get(session_id)
    if not state:
        return jsonify({"logs": [], "progress": 0, "pages_scanned": 0, "finished": True})
    return jsonify({
        "logs": state["logs"],
        "progress": state["progress"],
        "pages_scanned": state["pages_scanned"],
        "finished": state["finished"]
    })

@app.route("/cancel", methods=["POST"])
@login_required
def cancel():
    session_id = session.get("sid")
    state = crawl_states.get(session_id)
    if state:
        state["cancel"] = True
        state["logs"].append("⏹️ Crawl cancelled by user.")
    return jsonify({"status": "cancelled"})

@app.route("/export", methods=["GET"])
@login_required
def export():
    session_id = session.get("sid")
    state = crawl_states.get(session_id)
    if not state:
        return "No data", 404
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    domain_clean = state["domain"].replace('.', '_')
    filename = f"crawl_results_{domain_clean}_{timestamp}.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("Terry Ecom Link Checker Results\n")
        f.write(f"Checked Domain: {state['domain']}\n")
        f.write(f"Timestamp: {timestamp}\n\n")
        f.write("External/Malformed Mailto Links (and where found):\n")
        for link, sources in sorted(state["outbound_links"].items()):
            for src in sources:
                f.write(f"{link} (found on {src})\n")
        f.write("\nBroken Links (404s) and where found:\n")
        for link, sources in sorted(state["broken_links"].items()):
            for src in sources:
                f.write(f"{link} (found on {src})\n")
    return send_file(filename, as_attachment=True)

# --- INIT ---

@app.before_first_request
def before_first_request():
    init_db()

if __name__ == "__main__":
    init_db()
    app.run(debug=True)

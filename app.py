import os
import sqlite3
import threading
import time
import socket
from urllib.parse import urlparse, urljoin, urldefrag
from datetime import datetime
import secrets

import requests
from bs4 import BeautifulSoup
from flask import (
    Flask, render_template, request, jsonify, send_file, session,
    redirect, url_for, flash, abort, make_response
)
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin

# === CONFIG ===
ADMIN_EMAIL = "terry@terryecom.com"
ADMIN_PASSWORD = "Aph180912!!!"
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
APP_URL = os.environ.get("APP_URL", "https://yourdomain.com")
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', secrets.token_urlsafe(16))

# === FLASK-LOGIN SETUP ===
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

DB_PATH = "users.db"
CRAWL_STATES = {}
EXCLUDED_DOMAINS = [
    'g.co', 'facebook.com', 'instagram.com', 'x.com', 'twitter.com',
    'pinterest.com', 'shopify.com', 'edpb.europa.eu'
]

# === USER CLASS FOR FLASK-LOGIN ===
class User(UserMixin):
    def __init__(self, id, email, password_hash, verified, is_admin):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.verified = verified
        self.is_admin = is_admin

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0,
            verification_token TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    # Ensure admin exists
    cur = conn.execute("SELECT * FROM users WHERE email=?", (ADMIN_EMAIL,))
    if not cur.fetchone():
        conn.execute(
            "INSERT INTO users (email, password_hash, verified, is_admin) VALUES (?, ?, ?, ?)",
            (ADMIN_EMAIL, ADMIN_PASSWORD, 1, 1)
        )
    conn.commit()
    conn.close()

init_db()

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if row:
        return User(row["id"], row["email"], row["password_hash"], row["verified"], row["is_admin"])
    return None

# === EMAIL (BREVO) ===
def send_email_brevo(to_email, subject, html_content):
    if not BREVO_API_KEY:
        print("[WARN] BREVO_API_KEY not set, skipping email!")
        return False
    url = "https://api.brevo.com/v3/smtp/email"
    data = {
        "sender": {"name": "Link Checker", "email": ADMIN_EMAIL},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content,
    }
    headers = {
        "api-key": BREVO_API_KEY,
        "Content-Type": "application/json"
    }
    resp = requests.post(url, json=data, headers=headers, timeout=10)
    return resp.status_code == 201 or resp.status_code == 202

# === UTILS ===
def normalize_domain(domain):
    domain = domain.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def sanitize_input_url(input_url):
    url = input_url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        url = "https://" + parsed.path
    return url

def get_favicon_url(domain):
    return f"https://{domain}/favicon.ico"

# === CRAWLER LOGIC ===
def crawl_site(start_url, domain, session_id):
    state = CRAWL_STATES[session_id]
    state["logs"].append(f"🌐 Starting crawl: {start_url}")
    visited = set()
    to_visit = [start_url]
    outbound_links = {}
    broken_links = {}
    pages_scanned = 0
    state["max_progress_seen"] = 0
    should_cancel = lambda: CRAWL_STATES.get(session_id, {}).get("cancel", False)

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

# === ROUTES ===

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html", favicon_url="/static/favi.ico")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        pw = request.form["password"].strip()
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        if row and row["password_hash"] == pw and row["verified"]:
            user = User(row["id"], row["email"], row["password_hash"], row["verified"], row["is_admin"])
            login_user(user)
            return redirect(url_for("home"))
        flash("Invalid login or email not verified.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        pw = request.form["password"].strip()
        if not email or not pw:
            flash("Email and password required.", "danger")
            return redirect(url_for("register"))
        conn = get_db()
        existing = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            flash("Email already registered.", "danger")
            return redirect(url_for("register"))
        token = secrets.token_urlsafe(24)
        conn.execute(
            "INSERT INTO users (email, password_hash, verification_token) VALUES (?, ?, ?)",
            (email, pw, token)
        )
        conn.commit()
        conn.close()
        # Send verification email
        verify_url = f"{APP_URL}/verify/{token}"
        html = f"""
        <p>Welcome! Click to verify your email:</p>
        <a href="{verify_url}">{verify_url}</a>
        """
        send_email_brevo(email, "Verify your email for Link Checker", html)
        flash("Check your inbox to verify email!", "info")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/verify/<token>")
def verify(token):
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE verification_token=?", (token,)).fetchone()
    if row:
        conn.execute("UPDATE users SET verified=1, verification_token=NULL WHERE id=?", (row["id"],))
        conn.commit()
        conn.close()
        flash("Email verified, you may now log in.", "success")
        return redirect(url_for("login"))
    flash("Invalid or expired verification link.", "danger")
    return redirect(url_for("home"))

@app.route("/start_crawl", methods=["POST"])
@login_required
def start_crawl():
    input_url = request.form.get("url", "").strip()
    url = sanitize_input_url(input_url)
    if not url:
        return jsonify({"status": "error", "msg": "❌ Please enter a URL."}), 400

    parsed = urlparse(url)
    domain = normalize_domain(parsed.netloc)
    if not domain:
        domain = normalize_domain(urlparse("https://" + input_url).netloc)
        url = "https://" + domain
    session_id = session.get("sid") or str(time.time()) + str(os.getpid())
    session["sid"] = session_id

    try:
        socket.gethostbyname(domain)
    except socket.error:
        return jsonify({"status": "error", "msg": "❌ Domain does not exist or is unreachable!"}), 400

    CRAWL_STATES[session_id] = {
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
        "max_progress_seen": 0,
        "favicon_url": get_favicon_url(domain)
    }
    threading.Thread(target=crawl_site, args=(url, domain, session_id), daemon=True).start()
    return jsonify({"status": "started", "favicon_url": get_favicon_url(domain)})

@app.route("/progress", methods=["GET"])
@login_required
def progress():
    session_id = session.get("sid")
    state = CRAWL_STATES.get(session_id)
    if not state:
        return jsonify({"logs": [], "progress": 0, "pages_scanned": 0, "finished": True})
    return jsonify({
        "logs": state["logs"],
        "progress": state["progress"],
        "pages_scanned": state["pages_scanned"],
        "finished": state["finished"],
        "favicon_url": state.get("favicon_url", None)
    })

@app.route("/cancel", methods=["POST"])
@login_required
def cancel():
    session_id = session.get("sid")
    state = CRAWL_STATES.get(session_id)
    if state:
        state["cancel"] = True
        state["logs"].append("⏹️ Crawl cancelled by user.")
    return jsonify({"status": "cancelled"})

@app.route("/export", methods=["GET"])
@login_required
def export():
    session_id = session.get("sid")
    state = CRAWL_STATES.get(session_id)
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

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    verified = conn.execute("SELECT COUNT(*) FROM users WHERE verified=1").fetchone()[0]
    features = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]  # Example stat
    return render_template("admin.html", total=total, verified=verified)

@app.route("/feature_report", methods=["POST"])
@login_required
def feature_report():
    email = current_user.email
    name = request.form.get("name", "")
    msg = request.form.get("msg", "")
    full = f"From: {name or email} ({email})\n\n{msg}"
    # Email to admin
    send_email_brevo(ADMIN_EMAIL, "Feature/Bug Report", full.replace('\n','<br>'))
    return jsonify({"status": "ok"})

# ==== TEMPLATE RENDERERS ====
@app.context_processor
def inject_logo():
    return dict(
        logo_url="https://terryecom.com/LClogo.png",
        favicon_url="https://terryecom.com/favi.ico"
    )

# ========== TEMPLATES ==========
from flask import Markup
@app.template_global()
def render_header(title):
    return Markup(f"""
    <head>
        <meta charset="UTF-8">
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="icon" href="https://terryecom.com/favi.ico" type="image/x-icon">
        <link rel="shortcut icon" href="https://terryecom.com/favi.ico" type="image/x-icon">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    """)

# (Templates: You should still have `templates/index.html`, `login.html`, `register.html`, etc. See previous replies for full HTML if needed.)

if __name__ == "__main__":
    app.run(debug=True)

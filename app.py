import os
import threading
import time
import socket
import sqlite3
import secrets
from datetime import datetime
from urllib.parse import urlparse, urljoin, urldefrag

import requests
from bs4 import BeautifulSoup
from flask import (
    Flask, render_template, request, jsonify, send_file, session,
    redirect, url_for, flash
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user, UserMixin
)
from markupsafe import Markup

# === Flask Setup ===
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', secrets.token_hex(16))

# === Config ===
ADMIN_EMAIL = "terry@terryecom.com"
ADMIN_PASSWORD = "Aph180912!!!"
LOGO_URL = "https://terryecom.com/LClogo.png"
FAVICON_URL = "https://terryecom.com/favi.ico"
APP_URL = os.environ.get("APP_URL", "https://linky-ex7b.onrender.com")

# === Login Setup ===
login_manager = LoginManager()
login_manager.init_app(app)

# === DB Setup (sqlite) ===
DB = "users.db"
def db_connect():
    return sqlite3.connect(DB, check_same_thread=False)

def init_db():
    with db_connect() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            verify_token TEXT,
            created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

# === User Loader ===
class User(UserMixin):
    def __init__(self, id, name, email, password, verified):
        self.id = id
        self.name = name
        self.email = email
        self.password = password
        self.verified = verified

    @staticmethod
    def get(email):
        con = db_connect()
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if row:
            return User(*row[:5])
        return None

@login_manager.user_loader
def load_user(user_id):
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return User(*row[:5])
    return None

# === Crawler Setup ===
EXCLUDED_DOMAINS = [
    'g.co', 'facebook.com', 'instagram.com', 'x.com', 'twitter.com',
    'pinterest.com', 'shopify.com', 'edpb.europa.eu'
]
crawl_states = {}

# === Helpers ===
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

def send_brevo_email(to, subject, html, text):
    api_key = os.environ.get("BREVO_API_KEY")
    if not api_key:
        print("BREVO_API_KEY not set!")
        return
    data = {
        "sender": {"name": "Link Checker", "email": ADMIN_EMAIL},
        "to": [{"email": to}],
        "subject": subject,
        "htmlContent": html,
        "textContent": text,
    }
    requests.post(
        "https://api.brevo.com/v3/smtp/email",
        json=data,
        headers={"api-key": api_key, "Content-Type": "application/json"},
        timeout=15
    )

def crawl_site(start_url, domain, session_id):
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

# === Routes ===

@app.before_request
def ensure_db():
    if not os.path.exists(DB):
        init_db()

@app.route("/")
def index():
    return render_template("index.html", logo_url=LOGO_URL, favicon_url=FAVICON_URL)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        con = db_connect()
        cur = con.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if cur.fetchone():
            flash("Email already registered.", "danger")
            return redirect(url_for("signup"))
        verify_token = secrets.token_urlsafe(24)
        cur.execute(
            "INSERT INTO users (name, email, password, verify_token) VALUES (?,?,?,?)",
            (name, email, password, verify_token)
        )
        con.commit()
        # Send verification
        verify_link = f"{APP_URL}/verify?email={email}&token={verify_token}"
        send_brevo_email(
            to=email,
            subject="Verify your account",
            html=f"<p>Click to verify: <a href='{verify_link}'>{verify_link}</a></p>",
            text=f"Click to verify: {verify_link}"
        )
        flash("Check your email to verify your account!", "info")
        return redirect(url_for("login"))
    return render_template("signup.html", logo_url=LOGO_URL, favicon_url=FAVICON_URL)

@app.route("/verify")
def verify():
    email = request.args.get("email", "")
    token = request.args.get("token", "")
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT id, verify_token FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    if not row or row[1] != token:
        flash("Invalid verification link.", "danger")
        return redirect(url_for("login"))
    cur.execute("UPDATE users SET verified=1 WHERE id=?", (row[0],))
    con.commit()
    flash("Account verified. Please log in.", "success")
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = User.get(email)
        if not user or user.password != password:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))
        if not user.verified:
            flash("Please verify your email.", "warning")
            return redirect(url_for("login"))
        login_user(user)
        return redirect(url_for("index"))
    return render_template("login.html", logo_url=LOGO_URL, favicon_url=FAVICON_URL)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

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
    favicon_url = get_favicon_url(domain)
    crawl_states[session_id]["favicon_url"] = favicon_url

    threading.Thread(target=crawl_site, args=(url, domain, session_id), daemon=True).start()
    return jsonify({"status": "started", "favicon_url": favicon_url})

@app.route("/progress")
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
        "finished": state["finished"],
        "favicon_url": state.get("favicon_url", None)
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

@app.route("/export")
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

# === Admin Only ===
@app.route("/admin", methods=["GET", "POST"])
def admin():
    # Secret admin login
    if not session.get("admin"):
        if request.method == "POST":
            email = request.form.get("email")
            password = request.form.get("password")
            if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
                session["admin"] = True
            else:
                flash("Invalid admin credentials.", "danger")
                return redirect(url_for("admin"))
        else:
            return render_template("admin_login.html", logo_url=LOGO_URL, favicon_url=FAVICON_URL)
    # Stats page (very simple!)
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE verified=1")
    verified = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE verified=0")
    unverified = cur.fetchone()[0]
    return render_template("admin_stats.html", total_users=total_users, verified=verified, unverified=unverified, logo_url=LOGO_URL, favicon_url=FAVICON_URL)

@app.route("/feature", methods=["GET", "POST"])
def feature():
    if request.method == "POST":
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        message = request.form.get("message", "")
        subj = "[LINKY REPORT] Feature/Bug"
        send_brevo_email(
            to=ADMIN_EMAIL,
            subject=subj,
            html=f"<b>From:</b> {name} ({email})<br><pre>{Markup.escape(message)}</pre>",
            text=f"From: {name} ({email})\n\n{message}"
        )
        flash("Your feedback has been sent!", "success")
        return redirect(url_for("feature"))
    return render_template("feature.html", logo_url=LOGO_URL, favicon_url=FAVICON_URL)

# === Minimal template stubs ===
@app.context_processor
def inject_brand():
    return dict(logo_url=LOGO_URL, favicon_url=FAVICON_URL)

@app.errorhandler(404)
def page_not_found(e):
    return f"<h1>404 Not Found</h1>", 404

# === Run app ===
if __name__ == "__main__":
    if not os.path.exists(DB):
        init_db()
    app.run(debug=True)

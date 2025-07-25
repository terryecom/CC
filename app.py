import os
import threading
import time
import socket
import sqlite3
import secrets
from urllib.parse import urlparse, urljoin, urldefrag
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from flask import (
    Flask, render_template, request, jsonify, send_file, session, redirect, url_for, flash
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required, UserMixin, current_user
)

# ----------------------- SETTINGS & SECRETS --------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'terry_ecom_linkchecker')
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "terry@terryecom.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "CHANGEME")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
APP_URL = os.environ.get("APP_URL", "https://linky-ex7b.onrender.com")

LOGO_URL = "https://terryecom.com/LClogo.png"
FAVICON_URL = "https://terryecom.com/favi.ico"

EXCLUDED_DOMAINS = [
    'g.co', 'facebook.com', 'instagram.com', 'x.com', 'twitter.com',
    'pinterest.com', 'shopify.com', 'edpb.europa.eu'
]
crawl_states = {}

# --------------------- USER MODEL & DATABASE -------------------------

DATABASE = 'users.db'

class User(UserMixin):
    def __init__(self, id_, email, password, verified):
        self.id = id_
        self.email = email
        self.password = password
        self.verified = verified

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT,
            verified INTEGER,
            verify_token TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS usage_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT,
            action TEXT,
            ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(row["id"], row["email"], row["password"], row["verified"])
    return None

# ------------------------- EMAIL (BREVO) ----------------------------

def send_email(to, subject, html_content):
    if not BREVO_API_KEY:
        print("Brevo API key missing. Email not sent.")
        return False
    try:
        resp = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": BREVO_API_KEY,
                "accept": "application/json",
                "content-type": "application/json"
            },
            json={
                "sender": {"name": "Linky", "email": ADMIN_EMAIL},
                "to": [{"email": to}],
                "subject": subject,
                "htmlContent": html_content
            }
        )
        return resp.status_code == 201
    except Exception as e:
        print("Email send error:", e)
        return False

# ---------------------- DOMAIN & CRAWLER UTILS ----------------------

def normalize_domain(domain):
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def sanitize_input_url(input_url):
    url = input_url.strip()
    if not url:
        return ""
    # Add https:// if not present
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    # urlparse fix
    parsed = urlparse(url)
    if not parsed.netloc:
        url = "https://" + parsed.path
    parsed = urlparse(url)
    # Ensure netloc is present
    if not parsed.netloc:
        return ""
    return parsed.geturl()

def get_favicon_url(domain):
    return f"https://{domain}/favicon.ico"

def crawl_site(start_url, domain, session_id):
    state = crawl_states[session_id]
    state["logs"].append(f"🌐 Starting crawl: {start_url}")
    visited = set()
    to_visit = [start_url]
    outbound_links = {}  # url -> set(source_pages)
    broken_links = {}    # url -> set(source_pages)
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

                # Scan <a> tags for links
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

# ---------------------------- ROUTES --------------------------------

@app.route("/", methods=["GET"])
def index():
    favicon = FAVICON_URL
    logo = LOGO_URL
    return render_template("index.html", favicon=favicon, logo=logo)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        if c.fetchone():
            flash("Email already registered.", "danger")
            conn.close()
            return redirect(url_for("signup"))
        token = secrets.token_hex(16)
        c.execute("INSERT INTO users (email, password, verified, verify_token) VALUES (?, ?, 0, ?)", (email, password, token))
        conn.commit()
        conn.close()
        verify_link = f"{APP_URL}/verify/{token}"
        send_email(email, "Verify your account", f"Please verify your account: <a href='{verify_link}'>{verify_link}</a>")
        flash("Signup successful! Check your email for verification.", "success")
        return redirect(url_for("login"))
    favicon = FAVICON_URL
    logo = LOGO_URL
    return render_template("signup.html", favicon=favicon, logo=logo)

@app.route("/verify/<token>")
def verify(token):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE verify_token = ?", (token,))
    user = c.fetchone()
    if user:
        c.execute("UPDATE users SET verified = 1, verify_token = NULL WHERE id = ?", (user["id"],))
        conn.commit()
        flash("Email verified! You may now login.", "success")
    else:
        flash("Invalid or expired verification token.", "danger")
    conn.close()
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_dashboard"))
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        if user and user["password"] == password and user["verified"]:
            login_user(User(user["id"], user["email"], user["password"], user["verified"]))
            return redirect(url_for("index"))
        elif user and not user["verified"]:
            flash("Account not verified. Check your email.", "danger")
        else:
            flash("Login failed.", "danger")
    favicon = FAVICON_URL
    logo = LOGO_URL
    return render_template("login.html", favicon=favicon, logo=logo)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("login"))

@app.route("/feedback", methods=["POST"])
def feedback():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    msg = request.form.get("message", "")
    subject = "Linky Feature Request / Bug Report"
    html = f"""
        <b>Name:</b> {name}<br>
        <b>Email:</b> {email}<br>
        <b>Message:</b><br>
        {msg}
    """
    send_email(ADMIN_EMAIL, subject, html)
    flash("Feedback sent! Thank you.", "success")
    return redirect(url_for("index"))

@app.route("/start_crawl", methods=["POST"])
@login_required
def start_crawl():
    input_url = request.form.get("url", "").strip()
    url = sanitize_input_url(input_url)
    if not url:
        return jsonify({"status": "error", "msg": "❌ Please enter a valid URL."}), 400

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

    # Log usage
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO usage_log (user_email, action) VALUES (?, ?)", (current_user.email, f"crawl:{domain}"))
    conn.commit()
    conn.close()

    threading.Thread(target=crawl_site, args=(url, domain, session_id), daemon=True).start()
    return jsonify({"status": "started", "favicon_url": favicon_url})

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

# ------------------------- ADMIN DASHBOARD --------------------------

@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    if not session.get("admin"):
        return redirect(url_for("login"))
    # Show user stats & usage
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT email, verified FROM users")
    users = c.fetchall()
    c.execute("SELECT * FROM usage_log ORDER BY ts DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    favicon = FAVICON_URL
    logo = LOGO_URL
    return render_template("admin.html", users=users, logs=logs, favicon=favicon, logo=logo)

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("login"))

# --------------------------- RUN APP --------------------------------

if __name__ == "__main__":
    app.run(debug=True)

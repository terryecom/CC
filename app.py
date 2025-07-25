# app.py
import threading
import time
import requests
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify, send_file, session
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'terry_ecom_linkchecker')  # Needed for session

EXCLUDED_DOMAINS = [
    'g.co', 'facebook.com', 'instagram.com', 'x.com', 'twitter.com',
    'pinterest.com', 'shopify.com', 'edpb.europa.eu'
]

# Store per-session crawl state in memory
crawl_states = {}

def normalize_domain(domain):
    return domain.lower().replace("www.", "")

def crawl_site(start_url, domain, session_id):
    state = crawl_states[session_id]
    state["logs"].append(f"🌐 Starting crawl: {start_url}")
    visited = set()
    to_visit = [start_url]
    outbound_links = set()
    broken_links = set()
    pages_scanned = 0
    should_cancel = lambda: crawl_states.get(session_id, {}).get("cancel", False)

    while to_visit and not should_cancel():
        url = to_visit.pop(0)
        if url not in visited:
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 404:
                    broken_links.add(url)
                    state["logs"].append(f"❌ 404 Not Found: {url}")
                    continue
                soup = BeautifulSoup(response.text, "html.parser")
                visited.add(url)
                state["logs"].append(f"✅ Scanned: {url}")

                for a in soup.find_all("a", href=True):
                    href = a['href'].strip()
                    if href == "#" or href.lower().startswith(("javascript:", "tel:")):
                        continue
                    if href.startswith("mailto:"):
                        if domain not in href and href not in outbound_links:
                            outbound_links.add(href)
                            state["logs"].append(f"📧 Mailto: {href}")
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
                        if normalized_url not in outbound_links:
                            outbound_links.add(normalized_url)
                            state["logs"].append(f"🔗 Outbound: {normalized_url}")
                            try:
                                ext_resp = requests.get(normalized_url, timeout=5)
                                if ext_resp.status_code == 404:
                                    broken_links.add(normalized_url)
                                    state["logs"].append(f"❌ 404 External: {normalized_url}")
                            except Exception:
                                broken_links.add(normalized_url)
                                state["logs"].append(f"❌ Failed to load: {normalized_url}")

                pages_scanned += 1
                state["pages_scanned"] = pages_scanned
                state["progress"] = int((pages_scanned / (pages_scanned + len(to_visit))) * 100) if (pages_scanned + len(to_visit)) else 100
            except Exception:
                broken_links.add(url)
                state["logs"].append(f"❌ Failed to crawl: {url}")

        # Update state after each page
        state["visited"] = list(visited)
        state["outbound_links"] = list(outbound_links)
        state["broken_links"] = list(broken_links)
        state["progress"] = int((pages_scanned / (pages_scanned + len(to_visit))) * 100) if (pages_scanned + len(to_visit)) else 100
        state["pages_scanned"] = pages_scanned

    state["logs"].append(f"✅ Crawl complete. Outbound links: {len(outbound_links)}, 404s: {len(broken_links)}")
    state["progress"] = 100
    state["finished"] = True

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/start_crawl", methods=["POST"])
def start_crawl():
    url = request.form.get("url", "").strip()
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    domain = normalize_domain(parsed.netloc)
    session_id = session.get("sid") or str(time.time()) + str(os.getpid())
    session["sid"] = session_id

    # Create or reset state
    crawl_states[session_id] = {
        "logs": [],
        "progress": 0,
        "pages_scanned": 0,
        "visited": [],
        "outbound_links": [],
        "broken_links": [],
        "finished": False,
        "cancel": False,
        "start_url": url,
        "domain": domain
    }

    threading.Thread(target=crawl_site, args=(url, domain, session_id), daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/progress", methods=["GET"])
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
def cancel():
    session_id = session.get("sid")
    state = crawl_states.get(session_id)
    if state:
        state["cancel"] = True
        state["logs"].append("⏹️ Crawl cancelled by user.")
    return jsonify({"status": "cancelled"})

@app.route("/export", methods=["GET"])
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
        f.write("Outbound Links:\n")
        for link in sorted(state["outbound_links"]):
            f.write(link + "\n")
        f.write("\nBroken Links (404s):\n")
        for link in sorted(state["broken_links"]):
            f.write(link + "\n")
    return send_file(filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)

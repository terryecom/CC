import threading
import time
import socket
from urllib.parse import urlparse, urljoin, urldefrag
from datetime import datetime
import os

import requests
import whois
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify, send_file, session

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'terry_ecom_linkchecker')

EXCLUDED_DOMAINS = [
    'g.co', 'facebook.com', 'instagram.com', 'x.com', 'twitter.com',
    'pinterest.com', 'shopify.com', 'edpb.europa.eu'
]

crawl_states = {}

def normalize_domain(domain):
    return domain.lower().replace("www.", "")

def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        # Some WHOIS servers return lists for creation_date
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        registrar = w.registrar
        return str(created) if created else "Unknown", registrar if registrar else "Unknown"
    except Exception:
        return "Unknown", "Unknown"

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
                    if href.startswit

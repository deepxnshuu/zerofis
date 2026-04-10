import re
import requests
import time
import os
import ssl
import socket
import math
import joblib
from urllib.parse import urlparse

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ---------------- ML MODEL ----------------
try:
    model = joblib.load("model/phishing_model.pkl")
except:
    model = None

# ---------------- NORMALIZE URL ----------------
def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url

# ---------------- ENTROPY ----------------
def calculate_entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])

# ---------------- CLEAN DOMAIN ----------------
def clean_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if not domain:
        domain = parsed.path

    domain = domain.replace("www.", "").split(":")[0]
    return domain

# ---------------- BRAND IMPERSONATION ----------------
def is_fake_brand(domain):
    brands = ["google", "paypal", "facebook", "amazon", "microsoft", "apple"]

    for b in brands:
        if b in domain:
            # 🔥 Legit if ends with brand domain
            if domain.endswith(f"{b}.com"):
                return False

            # 🔥 Also allow subdomains like learn.microsoft.com
            if domain.count(".") <= 3 and domain.split(".")[-2] == b:
                return False

            return True

    return False

# ---------------- SSL ----------------
def get_ssl_info(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return True, "Unknown"

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])

                return True, issuer.get('organizationName', 'Trusted')

    except:
        return True, "Unknown"

# ---------------- VIRUSTOTAL ----------------
def check_virustotal(url):
    if not API_KEY:
        return 0

    try:
        headers = {"x-apikey": API_KEY}

        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if r.status_code != 200:
            return 0

        analysis_id = r.json()["data"]["id"]

        time.sleep(2)

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        stats = result.json()["data"]["attributes"]["stats"]

        return stats.get("malicious", 0) + stats.get("suspicious", 0)

    except:
        return 0

# ---------------- HELPERS ----------------
def suspicious_tld(domain):
    return bool(re.search(r"\.(ru|tk|ml|xyz|top|gq)$", domain))

def keyword_score(url):
    keywords = ["login", "verify", "secure", "account", "update", "bank", "password"]
    return sum(1 for k in keywords if k in url.lower())

# ---------------- MAIN ----------------
def analyze_url(url):
    try:
        url = normalize_url(url)
        domain = clean_domain(url)

        risk = 0
        threats = []

        length = len(url)
        subdomains = domain.count(".")
        hyphens = url.count("-")

        # ---------------- LENGTH ----------------
        if length > 100:
            risk += 10
            threats.append("Long URL")

        # ---------------- SUBDOMAIN ----------------
        if subdomains > 4:
            risk += 25
            threats.append("Too Many Subdomains")

        # ---------------- HYPHENS ----------------
        if hyphens > 4:
            risk += 10
            threats.append("Too Many Hyphens")

        # ---------------- ENTROPY ----------------
        entropy = calculate_entropy(domain)
        if entropy > 3.8:
            risk += 25
            threats.append("Randomized Domain")

        # ---------------- KEYWORDS ----------------
        kw = keyword_score(url)
        if kw >= 1:
            risk += 20
            threats.append("Suspicious Keyword in URL")

        # ---------------- COMBO RULE ----------------
        if entropy > 3.5 and "login" in url.lower():
            risk += 25
            threats.append("Suspicious Login on Random Domain")

        # ---------------- DOMAIN LENGTH BOOST ----------------
        if len(domain) > 12 and entropy > 3.5:
            risk += 10

        # ---------------- BRAND IMPERSONATION ----------------
        if is_fake_brand(domain):
            risk += 20
            threats.append("Brand Impersonation Detected")

        # ---------------- TLD ----------------
        if suspicious_tld(domain):
            risk += 20
            threats.append("Suspicious Domain TLD")

        # ---------------- SSL ----------------
        ssl_valid, issuer = get_ssl_info(url)

        # ---------------- API ----------------
        vt_score = check_virustotal(url)
        if vt_score >= 2:
            risk += 35
            threats.append("Flagged by Security Engines")

        # ---------------- ML ----------------
        if model:
            try:
                features_ml = [[
                    len(url),
                    url.count("-"),
                    len(re.findall(r'[^a-zA-Z0-9]', url)),
                    url.count(".")
                ]]

                if model.predict(features_ml)[0] == 1:
                    risk += 20
                    threats.append("ML Model Detection")

            except:
                pass

        # ---------------- HARD RULE ----------------
        if "login" in url.lower() and subdomains > 3:
            risk = max(risk, 70)

        # ---------------- FINAL ----------------
        if risk >= 55:
            result = "Phishing"
        elif risk >= 30:
            result = "Suspicious"
        else:
            result = "Safe"

        stats = {
            "url_length": length,
            "subdomain_depth": subdomains,
            "special_chars": len(re.findall(r'[^a-zA-Z0-9]', url)),
            "domain_age": "Unknown",
            "ssl_valid": "Yes" if ssl_valid else "No",
            "ssl_issuer": issuer,
            "confidence": min(risk, 100)
        }

        return result, min(risk, 100), threats, stats

    except Exception as e:
        return "Error", 0, [str(e)], {}
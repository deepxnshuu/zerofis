import re
import requests
import time
import ssl
import socket
from urllib.parse import urlparse

# ---------------- VIRUSTOTAL API ----------------
API_KEY = "YOUR_API_KEY_HERE"

def check_virustotal(url):
    headers = {"x-apikey": API_KEY}

    try:
        # submit URL
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:
            return 0

        analysis_id = response.json()["data"]["id"]

        time.sleep(2)

        # fetch result
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        stats = result.json()["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return malicious + suspicious

    except:
        return 0


# ---------------- SSL CHECK ----------------
def get_ssl_info(url):
    try:
        hostname = urlparse(url).hostname

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                issuer = dict(x[0] for x in cert['issuer'])
                issuer_name = issuer.get('organizationName', 'Unknown')

                return True, issuer_name

    except:
        return False, "Unknown"


# ---------------- DOMAIN CHECK ----------------
def suspicious_domain(url):
    return bool(re.search(r"\.ru|\.tk|\.ml|\.xyz|\.top", url))


# ---------------- FEATURE EXTRACTION ----------------
def extract_features(url):
    return {
        "url_length": len(url),
        "num_hyphens": url.count("-"),
        "num_special": len(re.findall(r'[^a-zA-Z0-9]', url)),
        "subdomain_depth": url.count("."),
    }


# ---------------- MAIN ANALYSIS ----------------
def analyze_url(url):
    features = extract_features(url)

    risk_score = 0
    threats = []

    # ---------------- LENGTH ----------------
    if features["url_length"] > 120:
        risk_score += 15
        threats.append("Very Long URL")
    elif features["url_length"] > 80:
        risk_score += 8
        threats.append("Long URL")

    # ---------------- HYPHENS ----------------
    if features["num_hyphens"] > 6:
        risk_score += 10
        threats.append("Too Many Hyphens")
    elif features["num_hyphens"] > 3:
        risk_score += 5
        threats.append("Multiple Hyphens")

    # ---------------- KEYWORDS ----------------
    keyword_matches = re.findall(
        r"login|secure|verify|update|bank|account|free|bonus",
        url.lower()
    )

    if len(keyword_matches) >= 2:
        risk_score += 15
        threats.append("Multiple Suspicious Keywords")

    # ---------------- SUBDOMAIN ----------------
    if features["subdomain_depth"] > 3:
        risk_score += 10
        threats.append("Too Many Subdomains")

    # ---------------- DOMAIN TYPE ----------------
    if suspicious_domain(url):
        risk_score += 25
        threats.append("Suspicious Domain TLD")

    # ---------------- SSL CHECK ----------------
    ssl_valid, ssl_issuer = get_ssl_info(url)

    if not ssl_valid:
        risk_score += 15
        threats.append("Invalid SSL Certificate")

    # ---------------- VIRUSTOTAL ----------------
    vt_score = check_virustotal(url)

    if vt_score >= 2:
        risk_score += 30
        threats.append("Flagged by Security Engines")

    # ---------------- FINAL DECISION ----------------
    if risk_score >= 60:
        result = "Phishing"
    elif risk_score >= 35:
        result = "Suspicious"
    else:
        result = "Safe"

    # ---------------- STATS ----------------
    stats = {
        "url_length": features["url_length"],
        "subdomain_depth": features["subdomain_depth"],
        "special_chars": features["num_special"],
        "domain_age": "Unknown",
        "ssl_valid": "Yes" if ssl_valid else "No",
        "ssl_issuer": ssl_issuer
    }

    return result, risk_score, threats, stats
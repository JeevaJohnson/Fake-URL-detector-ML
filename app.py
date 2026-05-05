from flask import Flask, request, jsonify
from flask_cors import CORS
import tldextract
from urllib.parse import urlparse
import socket
import ssl
import re
from functools import lru_cache

from model_utilities import model_predict

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# =========================
# CONSTANTS
# =========================
TRUSTED_DOMAINS = [
    "google.com", "amazon.in", "amazon.com",
    "facebook.com", "paypal.com", "microsoft.com",
    "wikipedia.org", "github.com", "stackoverflow.com"
]

HOSTING_DOMAINS = [
    "github.io", "netlify.app", "vercel.app",
    "firebaseapp.com", "herokuapp.com",
    "onrender.com", "pages.dev", "glitch.me"
]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]

KNOWN_BRANDS = ["google","amazon","paypal","facebook","hdfc","icici","sbi"]

# =========================
# HELPERS
# =========================
def normalize_url(url):
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def has_ip(url):
    return 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0

@lru_cache(maxsize=1000)
def has_dns(domain):
    try:
        socket.gethostbyname(domain)
        return 1
    except:
        return None

@lru_cache(maxsize=1000)
def has_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3):
            return 1
    except:
        return None

def looks_like_typo(domain):
    swaps = {'0':'o','1':'l','5':'s','@':'a'}
    return any(k in domain for k in swaps)

# =========================
# HEURISTICS (SEPARATE)
# =========================
def heuristic_checks(url, domain, features):
    h_score = 0
    reasons = []

    if features.get("fake_brand", 0):
        reasons.append("Brand impersonation")
        h_score += 0.4

    if features.get("brand_mismatch", 0):
        reasons.append("Domain mismatch")
        h_score += 0.3

    if features.get("domain_random", 0):
        reasons.append("Random domain")
        h_score += 0.2

    if features.get("num_keywords", 0) > 2:
        reasons.append("Too many suspicious keywords")
        h_score += 0.2

    if looks_like_typo(domain):
        reasons.append("Possible typo domain")
        h_score += 0.2

    if has_ip(url):
        reasons.append("Uses IP address")
        h_score += 0.3

    if not url.startswith("https"):
        reasons.append("Not using HTTPS")
        h_score += 0.2

    return h_score, reasons

# =========================
# REPUTATION (SEPARATE)
# =========================
def reputation_check(domain):
    for d in TRUSTED_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "trusted"
    return "unknown"

# =========================
# FINAL DECISION (COMBINER)
# =========================
def final_decision(url):
    url = normalize_url(url)

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    is_https = parsed.scheme == "https"

    # -------------------------
    # SHORTENER
    # -------------------------
    if any(domain.endswith(s) for s in SHORTENERS):
        return "Suspicious", 0.7, ["Shortened URL – destination unknown"]

    # -------------------------
    # HOSTING
    # -------------------------
    if any(domain.endswith(h) for h in HOSTING_DOMAINS):
        return "Suspicious", 0.7, ["Hosted on public platform"]

    # -------------------------
    # NETWORK CHECKS
    # -------------------------
    dns_status = has_dns(domain)
    ssl_status = has_ssl(domain)

    # -------------------------
    # MODEL
    # -------------------------
    try:
        prob, features = model_predict(url)
    except Exception as e:
        print("Model error:", e)
        prob, features = 0.3, {}

    # -------------------------
    # HEURISTICS
    # -------------------------
    h_score, h_reasons = heuristic_checks(url, domain, features)

    # -------------------------
    # REPUTATION
    # -------------------------
    rep = reputation_check(domain)

    # -------------------------
    # COMBINE SCORES
    # -------------------------
    risk_score = 0.6 * prob + 0.4 * h_score
    risk_score = max(0, min(risk_score, 1))

    # -------------------------
    # LABEL
    # -------------------------
    if risk_score >= 0.8:
        label = "Phishing"
    elif risk_score >= 0.5:
        label = "Suspicious"
    else:
        label = "Legitimate"

    # -------------------------
    # ADJUSTMENTS
    # -------------------------
    if rep == "trusted" and is_https:
        label = "Legitimate"
        risk_score = 0.95

    if not is_https and label == "Legitimate":
        label = "Suspicious"

    # -------------------------
    # REASONS
    # -------------------------
    reasons = []

    if rep == "trusted":
        reasons.append("Trusted domain")

    if is_https:
        reasons.append("Uses HTTPS")

    if ssl_status is None:
        reasons.append("SSL unknown")

    if dns_status is None:
        reasons.append("DNS not verified")

    reasons.extend(h_reasons)

    if not reasons:
        reasons.append("Looks normal")

    return label, round(risk_score, 2), reasons

# =========================
# ROUTES
# =========================
@app.route("/")
def home():
    return "Phishing Detector Running"

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()

        if not data or "url" not in data:
            return jsonify({"error": "No URL provided"}), 400

        url = data["url"]

        label, confidence, reasons = final_decision(url)

        return jsonify({
            "url": url,
            "prediction": label,
            "confidence": confidence,
            "reasons": reasons
        })

    except Exception as e:
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

# =========================
# RUN
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
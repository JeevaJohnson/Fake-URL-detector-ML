# =========================
# IMPORTS
# =========================
import re
import math
import numpy as np
import pandas as pd
import joblib
from collections import Counter
from urllib.parse import urlparse
from difflib import SequenceMatcher

# =========================
# LOAD MODEL
# =========================
model = joblib.load("ml_model.pkl")

# =========================
# CONSTANTS
# =========================
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "verify", "verification",
    "account", "update", "confirm", "password",
    "authentication", "session", "validate", "validation",
    "auth", "access", "security", "alert", "bank", "payment"
]

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]

TRUSTED_BRANDS = ["google", "amazon", "paypal", "microsoft", "bank", "apple","hdfc","icici","sbi"]

LEGIT_WORDS = ["wiki", "docs", "api", "github", "stackoverflow"]

# =========================
# HELPER FUNCTIONS
# =========================

def shannon_entropy(string):
    if len(string) == 0:
        return 0
    probs = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum(p * np.log2(p) for p in probs)


def domain_entropy(domain):
    if len(domain) == 0:
        return 0
    probs = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * np.log2(p) for p in probs)


def is_similar(a, b, threshold=0.8):
    return SequenceMatcher(None, a, b).ratio() > threshold


def normalize_text(s):
    return s.lower().replace("0", "o").replace("1", "l").replace("3", "e")


def detect_repeated_chars(domain):
    domain = domain.replace(".", "")
    return 1 if re.search(r'(.)\1{3,}', domain) else 0


def detect_fake_brand(url, domain):
    url = url.lower()
    domain = domain.lower()

    brands = ["google", "facebook", "amazon", "paypal", "apple", "microsoft"]

    for brand in brands:
        if brand in url and not domain.endswith(brand + ".com"):
            return 1
    return 0


def brand_mismatch(domain):
    for brand in TRUSTED_BRANDS:
        if brand in domain:
            if not domain.endswith(brand + ".com") and not domain.endswith(brand + ".in"):
                return 1
    return 0


# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features = {}

    # -------------------------
    # Domain randomness
    # -------------------------
    def entropy(s):
        prob = [n_x / len(s) for x, n_x in Counter(s).items()]
        return -sum(p * math.log2(p) for p in prob)

    features['domain_random'] = 1 if entropy(domain) > 4.2 else 0

    # -------------------------
    # Basic lexical features
    # -------------------------
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)

    features['num_dots'] = url.count('.')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0

    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['many_hyphens'] = 1 if features['num_hyphens'] >= 2 else 0

    # -------------------------
    # Protocol features
    # -------------------------
    features['has_https'] = 1 if url.startswith('https') else 0
    features['has_http'] = 1 if url.startswith('http://') else 0

    # -------------------------
    # Domain structure
    # -------------------------
    features['num_subdomains'] = domain.count('.')
    features['has_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0

    # -------------------------
    # Suspicious symbols
    # -------------------------
    features['has_at'] = 1 if '@' in url else 0
    features['has_double_slash'] = 1 if '//' in url[8:] else 0

    # -------------------------
    # Keyword features
    # -------------------------
    features['num_keywords'] = sum(1 for word in SUSPICIOUS_KEYWORDS if word in url)

    # -------------------------
    # Shortener detection
    # -------------------------
    features['is_shortened'] = 1 if any(s in domain for s in SHORTENERS) else 0

    # -------------------------
    # Entropy (full URL)
    # -------------------------
    ent = shannon_entropy(url)
    features['entropy'] = ent
    features['entropy_flag'] = 1 if (ent > 4.5 and features['num_digits'] > 2) else 0

    # -------------------------
    # Path features
    # -------------------------
    features['has_login_path'] = 1 if "login" in path else 0
    features['path_depth'] = path.count('/')

    # -------------------------
    # Advanced features
    # -------------------------
    features['brand_mismatch'] = brand_mismatch(domain)
    features['legit_path'] = 1 if any(w in url for w in LEGIT_WORDS) else 0
    features['fake_brand'] = detect_fake_brand(url, domain)
    features['repeated_chars'] = detect_repeated_chars(domain)
    features['http_login'] = 1 if url.startswith("http://") and "login" in url else 0

    return features


# =========================
# MODEL PREDICTION
# =========================
def model_predict(url):
    feats = extract_features(url)

    # IMPORTANT: consistent order
    feature_list = list(feats.values())
    X = pd.DataFrame([feature_list])

    prob = model.predict_proba(X)[0][1]

    return prob, feats



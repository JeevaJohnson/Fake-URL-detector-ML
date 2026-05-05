from flask import Flask, request, jsonify
import tldextract
from model_utilities import model_predict

app = Flask(__name__)

import re

def heuristic_checks(url, domain, features):
    h_score = 0
    reasons = []

    # 🔸 HTTP login (important)
    if features.get('http_login', 0):
        h_score += 0.3
        reasons.append("Login page over HTTP")

    # 🔸 Suspicious symbol
    if "@" in url:
        h_score += 0.2
        reasons.append("Contains @ symbol")

    # 🔸 Too many hyphens
    if domain.count('-') >= 2:
        h_score += 0.2
        reasons.append("Too many hyphens in domain")

    # 🔸 IP address usage
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        h_score += 0.3
        reasons.append("Uses IP address instead of domain")

    # 🔸 Keyword penalty (only if NOT trusted)
    if not any(domain.endswith(d) for d in TRUSTED_DOMAINS):
        if features.get('num_keywords', 0) > 2:
            h_score += 0.2
            reasons.append("Too many suspicious keywords")

    return h_score, reasons

def basic_url_sanity(url, domain):
    reasons = []

    if not domain or domain.startswith("."):
        reasons.append("Invalid domain structure")

    if "///" in url:
        reasons.append("Malformed URL")

    if ".." in domain:
        reasons.append("Suspicious domain (double dots)")

    return reasons
    
def explain_prediction(features):
    reasons = []

    if features.get('domain_random', 0) == 1:
        reasons.append("Random-looking domain")

    if features.get('entropy', 0) > 4:
        reasons.append("High randomness in URL")

    if features.get('num_digits', 0) > 5:
        reasons.append("Contains many digits")

    if features.get('num_keywords', 0) > 0:
        reasons.append("Contains phishing-related keywords")

    if features.get('has_ip', 0) == 1:
        reasons.append("Uses IP address instead of domain")

    if features.get('is_shortened', 0) == 1:
        reasons.append("Uses URL shortener")

    if features.get('num_subdomains', 0) > 3:
        reasons.append("Too many subdomains")

    if features.get('has_at', 0) == 1:
        reasons.append("Contains '@' symbol")

    if features.get('brand_mismatch', 0) == 1:
        reasons.append("Brand impersonation pattern")

    if features.get('fake_brand', 0) == 1:
        reasons.append("Fake brand spelling detected")

    if not reasons:
        reasons.append("Looks normal")

    return reasons
    
def build_output(label, confidence, reasons, is_https):
    # 🌐 Protocol
    protocol_msg = "Uses HTTPS (secure connection)" if is_https else "Uses HTTP (not secure)"

    # ⚠️ Safety
    if label == "Phishing":
        safety_msg = "🚨 Dangerous site – do not use"
    elif label == "Suspicious":
        safety_msg = "⚠ Not secure – use with caution"
    else:
        safety_msg = "✔ Safe to use"

    final_reasons = [
        f"⚠️ Safety: {safety_msg}",
        f"🌐 {protocol_msg}"
    ]

    final_reasons += ["- " + r for r in reasons]

    return label, confidence, final_reasons

    
def final_decision(url, calibrated_model):
    url = normalize_url(url)

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    is_https = parsed.scheme == "https"

    ext = tldextract.extract(domain)
    real_domain = ext.domain + "." + ext.suffix

    # =========================
    # 🔗 SHORTENER CHECK
    # =========================
    if any(domain.endswith(s) for s in SHORTENERS):
        return build_output(
            "Suspicious",
            0.7,
            ["Shortened URL – destination unknown"],
            is_https
        )

    # =========================
    # 🌐 HOSTING PLATFORM CHECK (FIXED)
    # =========================
    if any(domain.endswith(h) for h in HOSTING_DOMAINS):

        # 🚨 Phishing ONLY if brand misuse
        if any(b in domain for b in ["google","amazon","paypal","facebook","hdfc","icici","sbi"]):
            return build_output(
                "Phishing",
                0.9,
                ["Brand misuse on hosting platform"],
                is_https
            )

        # ⚠ Otherwise → always suspicious
        return build_output(
            "Suspicious",
            0.7,
            ["Hosted on public platform (user-controlled content)"],
            is_https
        )

    # =========================
    # 🌐 CORE FLAGS
    # =========================
    dns_status = has_dns(domain)
    ssl_status = has_ssl(domain)

    if not is_https:
        ssl_status = 0

    sanity_reasons = basic_url_sanity(url, domain)

    # =========================
    # 🚨 STRONG BRAND CHECK
    # =========================
    is_phish, reason = strong_phishing_check(url, domain)
    if is_phish:
        return build_output(
            "Phishing",
            0.95,
            ["Strong brand impersonation detected", reason],
            is_https
        )

    # =========================
    # 🤖 MODEL + HEURISTICS
    # =========================
    prob, features = model_predict(url, calibrated_model)
    h_score, _ = heuristic_checks(url, domain, features)
    rep = reputation_check(domain)

    reasons = {"positive": [], "negative": [], "neutral": []}

    # =========================
    # 🟢 POSITIVE
    # =========================
    if rep == "trusted":
        reasons["positive"].append("Trusted domain")

    if is_https and ssl_status == 1:
        reasons["positive"].append("Uses secure HTTPS")

    # =========================
    # 🔴 NEGATIVE
    # =========================
    if features.get("fake_brand", 0):
        reasons["negative"].append("Brand impersonation")
        h_score += 0.4

    if features.get("brand_mismatch", 0):
        reasons["negative"].append("Domain mismatch")
        h_score += 0.4

    if features.get("domain_random", 0):
        reasons["negative"].append("Random-looking domain")
        h_score += 0.2

    if looks_like_typo(domain) and any(b in domain for b in ["google","amazon","paypal","facebook"]):
        reasons["negative"].append("Possible typo-squatting domain")
        h_score += 0.3

    # =========================
    # 🌐 NETWORK / SSL
    # =========================
    if dns_status is None:
        reasons["negative"].append("Domain could not be verified")
        h_score += 0.15

    if ssl_status == 0:
        h_score += 0.2
    elif ssl_status is None:
        reasons["negative"].append("SSL status unknown")
        h_score += 0.1

    # =========================
    # 🚨 HARD RULES
    # =========================
    if "xn--" in domain:
        return build_output(
            "Phishing",
            0.95,
            ["Encoded (punycode) domain"],
            is_https
        )

    if has_ip(url):
        return build_output(
            "Suspicious",
            0.7,
            ["Uses IP instead of domain"],
            is_https
        )

    # =========================
    # 🚨 SANITY CHECK
    # =========================
    if "Invalid domain structure" in sanity_reasons:
        return build_output(
            "Phishing",
            0.95,
            sanity_reasons,
            is_https
        )

    if len(sanity_reasons) >= 2:
        return build_output(
            "Phishing",
            0.9,
            sanity_reasons,
            is_https
        )

    if len(sanity_reasons) == 1:
        reasons["negative"].extend(sanity_reasons)
        h_score += 0.2

    # =========================
    # 🔑 KEYWORDS
    # =========================
    suspicious_words = ["secure", "login", "verify", "account", "update", "auth"]
    keyword_count = sum(word in url.lower() for word in suspicious_words)

    if keyword_count > 0:
        reasons["negative"].append("Suspicious keywords")
        h_score += 0.2

    # =========================
    # 🚨 PHISHING RULES
    # =========================
    KNOWN_BRANDS = ["amazon","paypal","facebook","google","netflix","hdfc","icici","sbi"]

    if features.get("fake_brand", 0) and features.get("brand_mismatch", 0):
        return build_output(
            "Phishing",
            0.95,
            ["Strong brand impersonation"],
            is_https
        )

    if keyword_count >= 2 and real_domain not in TRUSTED_DOMAINS:

        if any(b in domain for b in KNOWN_BRANDS):
            return build_output(
                "Phishing",
                0.9,
                ["Generic phishing-style domain"],
                is_https
            )

        return build_output(
            "Suspicious",
            0.75,
            ["Multiple suspicious keywords"],
            is_https
        )

    for brand in KNOWN_BRANDS:
        if brand in domain:

            if real_domain in TRUSTED_DOMAINS:
                break

            if keyword_count >= 1:

                # 🚨 Strong phishing if domain looks like fake brand site
                if "-" in domain or len(domain.split(".")) == 2:
                    return build_output(
                        "Phishing",
                        0.9,
                        ["Brand-based phishing domain"],
                        is_https
                    )

    # =========================
    # ⚖️ FINAL SCORE (NO DL)
    # =========================
    risk_score = 0.6 * prob + 0.4 * h_score
    risk_score = max(0, min(risk_score, 1))
    
    if risk_score >= 0.84:
        label = "Phishing"
    elif risk_score >= 0.53:
        label = "Suspicious"
    else:
        label = "Legitimate"

    # =========================
    # 🛡 TRUST OVERRIDE
    # =========================
    if rep == "trusted" and is_https and ssl_status == 1:
        return build_output(
            "Legitimate",
            0.95,
            ["Trusted domain", "Uses secure HTTPS"],
            is_https
        )

    # =========================
    # 🚨 FINAL PHISHING GUARD
    # =========================
    if label == "Phishing":
        strong_signal = (
            features.get("fake_brand", 0) or
            features.get("brand_mismatch", 0) or
            any(b in domain for b in KNOWN_BRANDS)
        )

        if not strong_signal:
            label = "Suspicious"
            risk_score = min(risk_score, 0.8)

    # =========================
    # 🔄 FINAL CORRECTIONS
    # =========================
    if label == "Legitimate" and not is_https:
        label = "Suspicious"

    if label == "Legitimate" and (dns_status is None or ssl_status is None):
        label = "Suspicious"

    # =========================
    # 📊 CONFIDENCE
    # =========================
    if label == "Phishing":
        confidence = risk_score
    elif label == "Suspicious":
        confidence = 0.5 + (risk_score / 2)
    else:
        confidence = min(1 - risk_score, 0.85)

    # =========================
    # 📢 OUTPUT FORMAT
    # =========================
    protocol_msg = "Uses HTTPS (secure connection)" if is_https else "Uses HTTP (not secure)"

    if label == "Phishing":
        safety_msg = "🚨 Dangerous site – do not use"
    elif label == "Suspicious":
        safety_msg = "⚠ Not secure – use with caution"
    else:
        safety_msg = "✔ Safe to use"

    final_reasons = [f"⚠️ Safety: {safety_msg}", f"🌐 {protocol_msg}"]

    clean_reasons = [r.lstrip("- ").strip() for r in reasons["positive"] + reasons["negative"] + reasons["neutral"]]
    final_reasons += [f"- {r}" for r in clean_reasons]

    return label, round(confidence, 2), final_reasons    



# =========================
# ROUTES
# =========================
@app.route("/")
def home():
    return "Phishing Detector Running"


@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data["url"]

    label, confidence, reasons = final_decision(url)

    return jsonify({
        "url": url,
        "prediction": label,
        "confidence": round(confidence, 3),
        "reasons": reasons
    })


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    app.run(debug=True)

# app.py
"""
PhishRadar backend (Flask) - fully corrected
"""
import os
import time
import hashlib
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

# Optional libs
try:
    from transformers import pipeline
    hf_available = True
except Exception:
    hf_available = False

try:
    import whois
    whois_available = True
except Exception:
    whois_available = False

# Config
VT_API_KEY = os.environ.get("VT_API_KEY")  # optional VirusTotal API key
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024  # 10MB demo limit
REQUEST_TIMEOUT = 6  # seconds for outward requests

app = Flask(__name__, static_folder="static", static_url_path="/")
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = MAX_ATTACHMENT_SIZE

# Initialize optional text classifier
text_classifier = None
if hf_available:
    try:
        text_classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
        app.logger.info("Loaded transformers text-classification pipeline")
    except Exception as e:
        app.logger.warning(f"Failed to initialize transformers pipeline: {e}")
        text_classifier = None

# ---------- Helper Functions ----------
def now_ms():
    return int(time.time() * 1000)

def json_response(payload, status=200):
    return jsonify(payload), status

def safe_parse_url(url):
    if not url:
        return None
    try:
        return url.strip()
    except Exception:
        return None

def get_domain_from_url(url):
    try:
        p = urlparse(url)
        return p.netloc.split(":")[0].lower()
    except Exception:
        return None

def check_https(url):
    try:
        return urlparse(url).scheme.lower() == "https"
    except Exception:
        return False

def domain_age_days(domain: str):
    if not whois_available or not domain:
        return None
    try:
        info = whois.whois(domain)
        cd = getattr(info, "creation_date", None)
        if not cd:
            return None
        if isinstance(cd, list):
            cd = cd[0]
        if hasattr(cd, "year"):
            created = cd
        else:
            for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y.%m.%d", "%d.%m.%Y"):
                try:
                    created = datetime.strptime(str(cd), fmt)
                    break
                except Exception:
                    continue
            else:
                try:
                    created = datetime.fromisoformat(str(cd)[:19])
                except Exception:
                    return None
        return (datetime.now() - created).days
    except Exception:
        return None

def url_has_redirects(url):
    try:
        r = requests.head(url, allow_redirects=False, timeout=REQUEST_TIMEOUT)
        return 300 <= r.status_code < 400
    except Exception:
        try:
            r = requests.get(url, allow_redirects=True, timeout=REQUEST_TIMEOUT)
            return len(r.history) > 0
        except Exception:
            return False

def ssl_valid(url):
    try:
        if urlparse(url).scheme.lower() != "https":
            return False
        r = requests.get(url, timeout=REQUEST_TIMEOUT)
        return 200 <= r.status_code < 400
    except Exception:
        return False

def vt_file_report(file_hash: str):
    if not VT_API_KEY or not file_hash:
        return None
    try:
        headers = {"x-apikey": VT_API_KEY}
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        r = requests.get(url, headers=headers, timeout=10)
        return r.json() if r.status_code == 200 else {"error": f"vt_status_{r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def vt_url_lookup(url_to_check: str):
    if not VT_API_KEY or not url_to_check:
        return None
    try:
        headers = {"x-apikey": VT_API_KEY}
        submit = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url_to_check}, headers=headers, timeout=10)
        if submit.status_code not in (200, 201):
            return {"error": f"vt_submit_{submit.status_code}"}
        j = submit.json()
        analysis_id = j.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "no_analysis_id"}
        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=10)
        try:
            return analysis.json()
        except Exception:
            return {"error": "analysis_fetch_failed", "status_code": analysis.status_code, "raw": analysis.text}
    except Exception as e:
        return {"error": str(e)}

# ---------- Analysis Functions ----------
def analyze_url(url):
    url = safe_parse_url(url)
    t0 = now_ms()
    result = {"score": 0, "level": "safe", "message": "", "analysisItems": [], "scanTime": None, "dbChecks": 0, "aiConfidence": None, "vt": None}
    if not url:
        result.update({"score": 95, "level": "danger", "message": "Empty URL", "analysisItems": [{"icon": "🚨", "text": "No URL provided", "type": "danger"}]})
        result["scanTime"] = now_ms() - t0
        return result
    if not check_https(url):
        result["analysisItems"].append({"icon": "🔒", "text": "Missing HTTPS", "type": "danger"})
        result["score"] += 30
    if url_has_redirects(url):
        result["analysisItems"].append({"icon": "🔗", "text": "Contains redirects", "type": "danger"})
        result["score"] += 20
    domain = get_domain_from_url(url)
    age = domain_age_days(domain) if domain else None
    if age is not None:
        if age < 180:
            result["analysisItems"].append({"icon": "🚨", "text": f"Domain age is young ({age} days)", "type": "danger"})
            result["score"] += 25
        else:
            result["analysisItems"].append({"icon": "✅", "text": f"Domain age: {age} days", "type": "safe"})
    else:
        result["analysisItems"].append({"icon": "❓", "text": "Could not determine domain registration age", "type": "warning"})
        result["score"] += 5
    if not ssl_valid(url):
        result["analysisItems"].append({"icon": "🔐", "text": "SSL/HTTPS not valid or unreachable", "type": "danger"})
        result["score"] += 20
    if VT_API_KEY:
        vt = vt_url_lookup(url)
        result["vt"] = vt
    score = min(100, result["score"])
    level = "danger" if score >= 75 else ("warning" if score >= 40 else "safe")
    message = "HIGH RISK - strong indicators of phishing" if level == "danger" else ("MEDIUM RISK - suspicious patterns detected" if level == "warning" else "LOW RISK - content appears legitimate")
    result.update({"score": score, "level": level, "message": message, "scanTime": now_ms() - t0, "dbChecks": len(result["analysisItems"])})
    return result

def analyze_domain(domain):
    t0 = now_ms()
    result = {"score": 0, "level": "safe", "message": "", "analysisItems": [], "scanTime": None, "vt": None}
    if not domain:
        result.update({"score": 95, "level": "danger", "message": "Empty domain", "analysisItems": [{"icon": "🚨", "text": "No domain provided", "type": "danger"}], "scanTime": now_ms() - t0})
        return result
    domain = domain.strip().lower()
    age = domain_age_days(domain)
    if age is None:
        result["analysisItems"].append({"icon": "❓", "text": "Could not determine domain age", "type": "warning"})
        result["score"] += 10
    else:
        if age < 180:
            result["analysisItems"].append({"icon": "🚨", "text": f"Very new domain ({age} days)", "type": "danger"})
            result["score"] += 40
        else:
            result["analysisItems"].append({"icon": "✅", "text": f"Domain age: {age} days", "type": "safe"})
    if VT_API_KEY:
        result["vt"] = vt_url_lookup(domain)
    score = min(100, result["score"])
    level = "danger" if score >= 75 else ("warning" if score >= 40 else "safe")
    message = "HIGH RISK" if level == "danger" else ("MEDIUM RISK" if level == "warning" else "LOW RISK")
    result.update({"score": score, "level": level, "message": message, "scanTime": now_ms() - t0})
    return result

def analyze_text(text):
    t0 = now_ms()
    result = {"score": 0, "level": "safe", "message": "", "analysisItems": [], "scanTime": None, "aiConfidence": None}
    if not text or not text.strip():
        result.update({"score": 90, "level": "danger", "message": "Empty content", "analysisItems": [{"icon": "🚨", "text": "No content provided", "type": "danger"}], "scanTime": now_ms() - t0})
        return result
    heuristics_score = 0
    lowered = text.lower()
    urgent_words = ["urgent", "immediately", "verify", "update", "password", "bank", "login", "click here", "account suspended", "confirm"]
    hits = [w for w in urgent_words if w in lowered]
    if hits:
        heuristics_score += min(50, 10 * len(hits))
        result["analysisItems"].append({"icon": "⏱️", "text": f"Contains urgent keywords: {', '.join(hits[:5])}", "type": "danger"})
    if text_classifier:
        try:
            out = text_classifier(text[:1000])
            if isinstance(out, list) and len(out) > 0:
                label = out[0].get("label", "")
                score = float(out[0].get("score", 0))
                ai_conf = round(score * 100)
                if label.upper().startswith("NEG"):
                    heuristics_score += 15
                    result["analysisItems"].append({"icon": "🧠", "text": f"ML model shows negative tone (confidence {ai_conf}%)", "type": "warning"})
        except Exception:
            pass
    if "http://" in lowered or "https://" in lowered:
        heuristics_score += 10
        result["analysisItems"].append({"icon": "🔗", "text": "Contains embedded URL(s)", "type": "warning"})
    score = min(100, heuristics_score)
    level = "danger" if score >= 75 else ("warning" if score >= 40 else "safe")
    message = "HIGH RISK - Likely phishing" if level == "danger" else ("MEDIUM RISK - Possibly suspicious" if level == "warning" else "LOW RISK - Looks benign")
    result.update({"score": score, "level": level, "message": message, "scanTime": now_ms() - t0})
    return result

# ---------- Flask Routes ----------
@app.route("/", methods=["GET"])
def home():
    try:
        return app.send_static_file("phishradar.html")
    except Exception:
        return "Backend running. Place phishradar.html in ./static to serve UI.", 200

@app.route("/api/scan", methods=["POST"])
def scan():
    t0 = now_ms()
    try:
        content_type = request.content_type or ""
        if content_type.startswith("multipart/form-data") and 'file' in request.files:
            file = request.files.get("file")
            if not file:
                return json_response({"error": "no file uploaded"}, status=400)
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0)
            if size > MAX_ATTACHMENT_SIZE:
                return json_response({"error": "file too large (>10MB)"}, status=400)
            data = file.read()
            sha256 = hashlib.sha256(data).hexdigest()
            res = {"sha256": sha256, "size": size, "scanTime": now_ms() - t0}
            if VT_API_KEY:
                res["vt"] = vt_file_report(sha256)
            return json_response(res, status=200)
        payload = request.get_json(silent=True)
        if not payload:
            return json_response({"error": "invalid json body"}, status=400)
        typ = payload.get("type")
        content = payload.get("content", "")
        if typ == "url":
            return json_response(analyze_url(content))
        elif typ == "domain":
            return json_response(analyze_domain(content))
        elif typ in ("email", "text"):
            return json_response(analyze_text(content))
        else:
            return json_response({"error": "unknown type"}, status=400)
    except Exception:
        return json_response({"error": "internal server error"}, status=500)

# ---------- Run ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

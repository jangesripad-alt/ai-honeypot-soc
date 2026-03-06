from flask import Flask, render_template, request, redirect, jsonify
from pymongo import MongoClient
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import requests
import os

app = Flask(__name__)

# DATABASE CONNECTION
MONGO_URI = os.environ.get(
    "MONGO_URI",
    "mongodb+srv://YASH:SRIPAD@cluster0.jy5apii.mongodb.net/ai_honeypot?retryWrites=true&w=majority"
)

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

db = client["ai_honeypot"]
logs_collection = db["logs"]


# ATTACK CLASSIFICATION
def classify_attack(ip, username, password):

    now = datetime.utcnow()

    attempt_count = logs_collection.count_documents({"ip": ip})

    same_password_count = logs_collection.count_documents({
        "ip": ip,
        "password": password
    })

    recent_attempts = logs_collection.count_documents({
        "ip": ip,
        "timestamp": {"$gte": now - timedelta(seconds=10)}
    })

    attack_type = "Normal"
    risk_level = "Low"

    if attempt_count > 8:
        attack_type = "Brute Force"
        risk_level = "High"

    elif same_password_count > 6:
        attack_type = "Credential Stuffing"
        risk_level = "High"

    elif recent_attempts > 10:
        attack_type = "Bot Attack"
        risk_level = "High"

    return attack_type, risk_level, attempt_count + 1


# GEO LOCATION
def get_geo(ip):

    country = "Unknown"
    city = "Unknown"
    lat = None
    lon = None

    try:
        geo = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=3
        ).json()

        country = geo.get("country")
        city = geo.get("city")
        lat = geo.get("lat")
        lon = geo.get("lon")

    except:
        pass

    return country, city, lat, lon


# SAVE ATTACK LOG
def log_attack(service, username, password):

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    user_agent = request.headers.get("User-Agent")

    timestamp = datetime.utcnow()

    attack_type, risk_level, attempt_count = classify_attack(
        ip, username, password
    )

    country, city, lat, lon = get_geo(ip)

    logs_collection.insert_one({

        "service": service,
        "ip": ip,
        "username": username,
        "password": password,
        "user_agent": user_agent,

        "timestamp": timestamp,
        "attempt_count": attempt_count,

        "attack_type": attack_type,
        "risk_level": risk_level,

        "country": country,
        "city": city,

        "lat": lat,
        "lon": lon
    })


# MAIN LOGIN
@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "secure123":
            return redirect("/dashboard")

        log_attack("web_login", username, password)

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


# ADMIN PANEL HONEYPOT
@app.route("/admin", methods=["GET", "POST"])
def admin_panel():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        log_attack("admin_panel", username, password)

        return render_template("login.html", error="Access Denied")

    return render_template("login.html")


# DASHBOARD
@app.route("/dashboard")
def dashboard():

    logs = list(logs_collection.find().sort("timestamp", -1))

    total_attempts = len(logs)

    attack_counts = Counter(
        [log.get("attack_type") for log in logs]
    )

    brute_force_count = attack_counts.get("Brute Force", 0)
    suspicious_count = attack_counts.get("Credential Stuffing", 0)
    normal_count = attack_counts.get("Normal", 0)

    unique_ips = len(set(
        log.get("ip") for log in logs
    ))

    ips = [log.get("ip") for log in logs]
    users = [log.get("username") for log in logs]
    attempts = [log.get("attempt_count", 0) for log in logs]
    attacks = [log.get("attack_type") for log in logs]

    top_ip = Counter(ips).most_common(1)[0][0] if ips else "N/A"
    top_user = Counter(users).most_common(1)[0][0] if users else "N/A"
    top_attack = Counter(attacks).most_common(1)[0][0] if attacks else "N/A"
    highest_attempt = max(attempts) if attempts else 0

    timeline = defaultdict(int)

    for log in logs:

        ts = log.get("timestamp")

        if ts:
            key = ts.strftime("%H:%M")
            timeline[key] += 1

    timeline_labels = sorted(timeline.keys())
    timeline_counts = [timeline[k] for k in timeline_labels]

    attack_locations = []

    for log in logs:

        lat = log.get("lat")
        lon = log.get("lon")

        if lat and lon:

            attack_locations.append({
                "lat": lat,
                "lon": lon
            })

    return render_template(

        "dashboard.html",

        logs=logs,

        total_attempts=total_attempts,
        brute_force_count=brute_force_count,
        suspicious_count=suspicious_count,
        normal_count=normal_count,

        unique_ips=unique_ips,

        top_ip=top_ip,
        top_user=top_user,
        highest_attempt=highest_attempt,
        top_attack=top_attack,

        timeline_labels=timeline_labels,
        timeline_counts=timeline_counts,

        attack_locations=attack_locations
    )


# API LOGS
@app.route("/api/logs")
def api_logs():

    logs = list(
        logs_collection
        .find()
        .sort("timestamp", -1)
        .limit(100)
    )

    for log in logs:
        log["_id"] = str(log["_id"])

    return jsonify(logs)


# RUN SERVER
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, time, os
from scanner import analyze_url          # ← correct function
from passwordcheck import check_strength, generate_password

app = Flask(__name__)
CORS(app, origins="*")   # allow all frontend origins

history = []
stats = {
    "total": 0,
    "safe": 0,
    "unsafe": 0,
    "safety_points": 0,
    "recent_threats": []
}

# ------------------ URL SCANNER API ---------------------

@app.post("/api/scan")
def api_scan():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL required"}), 400

    # ---------------- FIXED ----------------
    result = analyze_url(url)   # ← use analyze_url from scanner.py

    # convert status to uppercase for consistency
    status = result.get("status", "").upper()

    stats["total"] += 1
    if status == "SAFE":
        stats["safe"] += 1
        stats["safety_points"] += 1
    else:
        stats["unsafe"] += 1
        stats["recent_threats"].insert(0, {
            "url": url,
            "score": result.get("score"),
            "timestamp": int(time.time())
        })
        stats["recent_threats"] = stats["recent_threats"][:5]

    history.append({
        "url": url,
        "result": status,
        "score": result.get("score"),
        "timestamp": int(time.time())
    })

    return jsonify(result)

@app.get("/api/stats")
def api_stats():
    return jsonify(stats)

@app.get("/api/history")
def api_history():
    return jsonify(history)

# ------------------ PASSWORD CHECK API ---------------------

@app.post("/api/check_password")
def api_check_password():
    data = request.get_json()
    password = data.get("password")

    if not password:
        return jsonify({"error": "Password required"}), 400

    result_text = check_strength(password)

    if result_text.startswith("Invalid"):
        status = "INVALID"
    elif result_text.startswith("Weak"):
        status = "WEAK"
    elif result_text.startswith("Fine"):
        status = "FINE"
    elif result_text.startswith("Good"):
        status = "GOOD"
    else:
        status = "STRONG"

    return jsonify({
        "password": password,
        "status": status,
        "message": result_text
    })

@app.get("/api/generate_password")
def api_generate_password():
    strength = request.args.get("strength", "strong")
    pwd = generate_password(strength)
    return jsonify({
        "strength": strength,
        "password": pwd
    })

# ----------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)

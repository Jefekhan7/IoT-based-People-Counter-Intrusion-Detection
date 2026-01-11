

from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
import base64
import json
import time

app = Flask(__name__)

AES_KEY = b"\x10\x21\x32\x43\x54\x65\x76\x87\x98\xA9\xBA\xCB\xDC\xED\xFE\x0F"
AUTH = "SECRET_TOKEN"

events = []
seen_seqs = set()

people_inside = 0
total_entered = 0      # NEW: Total people who ever entered
armed = True
total_intrusions = 0

def decrypt(cipher_b64: str) -> str:
    try:
        raw = base64.b64decode(cipher_b64)
        if len(raw) % 16 != 0:
            return "BLOCK ERROR"
        cipher = AES.new(AES_KEY, AES.MODE_ECB)  
        pt = cipher.decrypt(raw).rstrip(b'\x00')
        return pt.decode('utf-8')
    except Exception as e:
        print("Decrypt error:", e)
        return "DECRYPTION FAILURE"

def verify_hmac(cipher: str, received_hmac: str) -> bool:
    calc = sum(ord(c) for c in cipher)
    return format(calc, 'X') == received_hmac.upper()

@app.route("/")
def dashboard():
    return render_template("index.html")

@app.route("/arm", methods=["POST"])
def set_arm():
    global armed
    data = request.get_json(silent=True) or {}
    armed = data.get("armed", armed)
    return jsonify({"armed": armed})

@app.route("/how-it-works")  # NEW ROUTE - matches the button in your dashboard
def how_it_works():
    return render_template("how.html")

# Optional redirect if someone uses old link
@app.route("/how")
def how_redirect():
    return render_template("how.html")


@app.route("/summary")
def summary():
    return jsonify({
        "people": people_inside,
        "total_entered": total_entered,     # NEW
        "armed": armed,
        "intrusions": total_intrusions,
        "events": len(events)
    })

@app.route("/event", methods=["POST"])
def event():
    global people_inside, total_entered, total_intrusions

    if request.headers.get("Authorization") != f"Bearer {AUTH}":
        return "unauthorized", 401

    data = request.get_json(silent=True)
    if not data or "cipher" not in data or "hmac" not in data:
        return "bad request", 400

    intrusion = False
    payload = {}

    if not verify_hmac(data["cipher"], data["hmac"]):
        intrusion = True
    else:
        decrypted = decrypt(data["cipher"])
        try:
            payload = json.loads(decrypted)
        except:
            intrusion = True

    seq = payload.get("seq")
    if seq is not None and seq in seen_seqs:
        intrusion = True
    else:
        if seq is not None:
            seen_seqs.add(seq)

    event_type = payload.get("type", "UNKNOWN")

    # Only update people count when system is DISARMED
    if not payload.get("armed", True):
        if event_type == "ENTRY":
            people_inside += 1
            total_entered += 1   # NEW: Count every entry forever
        elif event_type == "EXIT":
            if people_inside > 0:
                people_inside -= 1

    # Intrusion logic
    if payload.get("intrusion") or intrusion:
        total_intrusions += 1
        intrusion = True

    record = {
        "time": time.strftime("%H:%M:%S"),
        "event": event_type,
        "people": people_inside,
        "armed": payload.get("armed", armed),
        "intrusion": intrusion,
        "device": payload.get("device"),
        "seq": seq,
        "decrypted": json.dumps(payload) if payload else decrypted,
        "encrypted": data["cipher"]
    }
    events.append(record)

    return jsonify({"ACK": True})

@app.route("/events")
def get_events():
    return jsonify(events[-20:])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

PRIVATE_SECRET = "YOUR_PRIVATE_SECRET_KEY"

def sha512(text):
    return hashlib.sha512(text.encode()).hexdigest()

@app.route("/callback", methods=["POST"])
def callback():
    received_key = request.headers.get("x-private-key")
    expected_key = sha512(PRIVATE_SECRET)

    if received_key != expected_key:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    print("CALLBACK:", data)

    if data["status"] == "SUCCESS":
        print("✅ Paiement confirmé")

    return jsonify({"ok": True})

app.run(port=5000)

# kms_api.py
from flask import Flask, request, jsonify
from kms_core import KMS
import os
import json

app = Flask(__name__)
kms = KMS()
MESSAGE_FILE = "messages.json"
REGISTERED_FILE = "registered_users.json"

# Load or initialize registered users
if os.path.exists(REGISTERED_FILE):
    with open(REGISTERED_FILE, "r") as f:
        registered_users = set(json.load(f))
else:
    registered_users = set()

def save_registered_users():
    with open(REGISTERED_FILE, "w") as f:
        json.dump(list(registered_users), f)

@app.route("/")
def home():
    return jsonify({"message": "KMS API is running!"})

def load_messages():
    if os.path.exists(MESSAGE_FILE):
        with open(MESSAGE_FILE, "r") as f:
            return json.load(f)
    return []

def save_message(sender, recipient, encrypted, algorithm):
    messages = load_messages()
    messages.append({
        "sender": sender,
        "recipient": recipient,
        "encrypted": encrypted,
        "algorithm": algorithm
    })
    with open(MESSAGE_FILE, "w") as f:
        json.dump(messages, f)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    user = data.get("user")
    if not user:
        return jsonify({"error": "Missing 'user' field"}), 400
    kms.generate_user_keys(user)
    registered_users.add(user)
    save_registered_users()
    return jsonify({"message": f"User '{user}' registered."})

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    sender = data.get("sender")
    recipient = data.get("recipient")
    message = data.get("message")
    algorithm = data.get("algorithm", "RSA")

    if not all([sender, recipient, message]):
        return jsonify({"error": "Missing fields in request"}), 400

    if sender not in registered_users or recipient not in registered_users:
        return jsonify({"error": "Sender or recipient is not registered."}), 403

    encrypted = kms.encrypt_for_user(recipient, message, algorithm=algorithm)
    save_message(sender, recipient, encrypted, algorithm)

    return jsonify({"encrypted": encrypted})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    user = data.get("user")
    encrypted = data.get("encrypted")
    algorithm = data.get("algorithm", "RSA")

    if not all([user, encrypted]):
        return jsonify({"error": "Missing fields in request"}), 400

    if user not in registered_users:
        return jsonify({"error": "User is not registered."}), 403

    try:
        decrypted = kms.decrypt_for_user(user, encrypted, algorithm=algorithm)
        return jsonify({"decrypted": decrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/inbox/<user>", methods=["GET"])
def inbox(user):
    if user not in registered_users:
        return jsonify({"error": "User is not registered."}), 403

    messages = load_messages()
    user_messages = []

    for msg in messages:
        if msg["recipient"] == user:
            algorithm = msg.get("algorithm", "RSA")
            try:
                decrypted = kms.decrypt_for_user(user, msg["encrypted"], algorithm=algorithm)
            except:
                decrypted = "[Unable to decrypt]"
            user_messages.append({
                "sender": msg["sender"],
                "decrypted": decrypted,
                "algorithm": algorithm
            })

    return jsonify(user_messages)

if __name__ == "__main__":
    app.run(debug=True)
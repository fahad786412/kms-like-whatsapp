# app.py
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room
from kms_core import KMS
import json
import os

app = Flask(__name__, template_folder="templates", static_folder="static")
socketio = SocketIO(app)
kms = KMS()

MESSAGE_FILE = "messages.json"
# Shared registration file with kms_api.py
REGISTERED_FILE = os.path.join(os.path.dirname(__file__), "registered_users.json")

# Load or initialize registered users
if os.path.exists(REGISTERED_FILE):
    with open(REGISTERED_FILE, "r") as f:
        registered_users = set(json.load(f))
else:
    registered_users = set()

def save_registered_users():
    with open(REGISTERED_FILE, "w") as f:
        json.dump(list(registered_users), f)

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

user_sessions = dict()

@app.route("/")
def index():
    return render_template("chat.html")

@socketio.on("register")
def handle_register(data):
    user = data["user"]
    if user not in registered_users:
        kms.generate_user_keys(user)
        registered_users.add(user)
        save_registered_users()
    emit("registered", {"message": f"User '{user}' registered."})

@socketio.on("join")
def on_join(data):
    username = data["username"]
    if username not in registered_users:
        emit("error", {"message": f"User '{username}' is not registered."})
        return
    user_sessions[request.sid] = username
    join_room(username)
    emit("receive_message", {
        "sender": "System",
        "recipient": username,
        "decrypted": f"{username} has joined."
    }, room=username)

@socketio.on("send_message")
def handle_message(data):
    sid = request.sid
    sender = user_sessions.get(sid)
    recipient = data["recipient"]
    message = data["message"]
    algorithm = data.get("algorithm", "RSA")

    if sender not in registered_users or recipient not in registered_users:
        emit("error", {"message": "Sender or recipient is not registered."})
        return

    encrypted = kms.encrypt_for_user(recipient, message, algorithm=algorithm)
    try:
        decrypted = kms.decrypt_for_user(recipient, encrypted, algorithm=algorithm)
    except:
        decrypted = "[Only recipient can decrypt]"

    save_message(sender, recipient, encrypted, algorithm)

    emit("receive_message", {
        "sender": sender,
        "recipient": recipient,
        "encrypted": encrypted,
        "decrypted": decrypted,
        "algorithm": algorithm
    }, room=recipient)

@socketio.on("fetch_messages")
def handle_fetch_messages(data):
    username = data["username"]
    if username not in registered_users:
        emit("error", {"message": f"User '{username}' is not registered."})
        return

    user_messages = []
    for msg in load_messages():
        if msg["recipient"] == username:
            algorithm = msg.get("algorithm", "RSA")
            try:
                decrypted = kms.decrypt_for_user(username, msg["encrypted"], algorithm=algorithm)
            except:
                decrypted = "[Unable to decrypt]"
            user_messages.append({
                "sender": msg["sender"],
                "decrypted": decrypted,
                "algorithm": algorithm
            })
    emit("inbox", user_messages)

if __name__ == "__main__":
    socketio.run(app, debug=True)
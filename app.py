from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import re

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "trustvault-hackathon-secret-key-2026"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

# In-memory store (hackathon demo)
users = {}
secrets_store = {}

def is_strong_password(pw):
    if len(pw) < 8: return False
    if not re.search(r"[A-Z]", pw): return False
    if not re.search(r"[a-z]", pw): return False
    if not re.search(r"[0-9]", pw): return False
    return True

@app.route("/")
def home():
    return jsonify({"message": "TrustVault API running", "status": "secure"})

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    # Input validation
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if len(username) < 3 or len(username) > 30:
        return jsonify({"error": "username must be 3-30 chars"}), 400
    if username in users:
        return jsonify({"error": "user already exists"}), 409
    if not is_strong_password(password):
        return jsonify({"error": "password must be 8+ chars with upper, lower, number"}), 400

    users[username] = generate_password_hash(password)
    secrets_store[username] = []
    return jsonify({"message": "user registered successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    if username not in users or not check_password_hash(users[username], password):
        return jsonify({"error": "invalid credentials"}), 401

    token = create_access_token(identity=username)
    return jsonify({"access_token": token}), 200

@app.route("/secrets", methods=["POST"])
@jwt_required()
def add_secret():
    username = get_jwt_identity()
    data = request.get_json()
    secret = data.get("secret", "").strip()

    if not secret or len(secret) > 500:
        return jsonify({"error": "secret must be 1-500 chars"}), 400

    secrets_store[username].append(secret)
    return jsonify({"message": "secret stored"}), 201

@app.route("/secrets", methods=["GET"])
@jwt_required()
def get_secrets():
    username = get_jwt_identity()
    return jsonify({"secrets": secrets_store.get(username, [])}), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret-key-change-in-prod'
jwt = JWTManager(app)

# Step 4: Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

# Encryption key
key = Fernet.generate_key()
fernet = Fernet(key)

users = {}
secrets = {}

@app.route('/')
def home():
    return jsonify({
        "message": "TrustVault API is LIVE 🚀",
        "status": "Running",
        "endpoints": ["/register", "/login", "/store", "/retrieve"]
    })

@app.route('/health')
def health():
    return jsonify({"status": "ok"})
@app.route('/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if username in users:
        return jsonify({"error": "User exists"}), 400
    users[username] = password
    return jsonify({"msg": "User created"}), 201

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if users.get(username) != password:
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_access_token(identity=username)
    return jsonify(access_token=token), 200

@app.route('/store', methods=['POST'])
@jwt_required()
def store_secret():
    current_user = get_jwt_identity()
    data = request.get_json()
    secret = data.get('secret')
    if not secret:
        return jsonify({"error": "Secret required"}), 400
    encrypted = fernet.encrypt(secret.encode()).decode()
    secrets[current_user] = encrypted
    return jsonify({"msg": "Secret stored securely"}), 200

@app.route('/retrieve', methods=['GET'])
@jwt_required()
def retrieve_secret():
    current_user = get_jwt_identity()
    encrypted = secrets.get(current_user)
    if not encrypted:
        return jsonify({"error": "No secret found"}), 404
    decrypted = fernet.decrypt(encrypted.encode()).decode()
    return jsonify({"secret": decrypted}), 200

if __name__ == '__main__':
    app.run(debug=True)

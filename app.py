from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import sqlite3
import os
from functools import wraps

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "trustvault-secret-2026")
DATABASE = "trustvault.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS documents 
                 (id INTEGER PRIMARY KEY, name TEXT, owner_id INTEGER, category TEXT, content TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS permissions 
                 (id INTEGER PRIMARY KEY, doc_id INTEGER, user_id INTEGER, permission TEXT, UNIQUE(doc_id, user_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs 
                 (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, doc_id INTEGER, details TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    # Seed 3 roles
    try:
        c.execute("INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (1, 'admin', ?, 'admin')", (generate_password_hash("admin123"),))
        c.execute("INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (2, 'owner', ?, 'owner')", (generate_password_hash("owner123"),))
        c.execute("INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES (3, 'viewer', ?, 'viewer')", (generate_password_hash("viewer123"),))
    except: pass
    conn.commit()
    conn.close()

init_db()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            g.current_user = data
        except:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def log_audit(user_id, action, doc_id=None, details=""):
    conn = get_db()
    conn.execute("INSERT INTO audit_logs (user_id, action, doc_id, details) VALUES (?, ?, ?, ?)", 
                 (user_id, action, doc_id, details))
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return jsonify({"message": "TrustVault API - Secure Document Sharing", "status": "live", "roles": "admin/owner/viewer"})

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "username, password required"}), 400
    role = data.get('role', 'viewer')
    if role not in ['admin', 'owner', 'viewer']:
        role = 'viewer'
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     (data['username'], generate_password_hash(data['password']), role))
        conn.commit()
        return jsonify({"message": "User created", "role": role})
    except sqlite3.IntegrityError:
        return jsonify({"error": "User exists"}), 400
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (data.get('username'),)).fetchone()
    conn.close()
    if not user or not check_password_hash(user['password_hash'], data.get('password')):
        return jsonify({"error": "Invalid credentials"}), 401
    token = jwt.encode({
        "user_id": user['id'],
        "username": user['username'],
        "role": user['role'],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token, "role": user['role'], "user_id": user['id']})

@app.route("/upload", methods=["POST"])
@token_required
def upload():
    # Validation
    data = request.json
    name = data.get('name', '').strip()
    content = data.get('content', '')
    category = data.get('category', 'general')
    
    if not name or len(name) > 100:
        return jsonify({"error": "Invalid name"}), 400
    if len(content) > 10000:
        return jsonify({"error": "Content too large - max 10KB"}), 400
    if category not in ['finance', 'legal', 'hr', 'general', 'contracts']:
        category = 'general'
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO documents (name, owner_id, category, content) VALUES (?, ?, ?, ?)",
                (name, g.current_user['user_id'], category, content))
    doc_id = cur.lastrowid
    # Owner gets edit permission auto
    cur.execute("INSERT INTO permissions (doc_id, user_id, permission) VALUES (?, ?, 'edit')",
                (doc_id, g.current_user['user_id']))
    conn.commit()
    conn.close()
    log_audit(g.current_user['user_id'], 'upload', doc_id, f"name={name}")
    return jsonify({"message": "Document uploaded", "doc_id": doc_id})

@app.route("/documents", methods=["GET"])
@token_required
def list_docs():
    conn = get_db()
    # Only docs where user has permission or is admin
    if g.current_user['role'] == 'admin':
        docs = conn.execute("SELECT d.*, u.username as owner_name FROM documents d JOIN users u ON d.owner_id=u.id").fetchall()
    else:
        docs = conn.execute("""
            SELECT d.*, u.username as owner_name FROM documents d 
            JOIN users u ON d.owner_id=u.id
            JOIN permissions p ON p.doc_id=d.id 
            WHERE p.user_id=?
        """, (g.current_user['user_id'],)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in docs])

@app.route("/documents/<int:doc_id>", methods=["GET"])
@token_required
def get_doc(doc_id):
    conn = get_db()
    # Server decides every time - check permission
    if g.current_user['role'] != 'admin':
        perm = conn.execute("SELECT * FROM permissions WHERE doc_id=? AND user_id=?", 
                            (doc_id, g.current_user['user_id'])).fetchone()
        if not perm:
            log_audit(g.current_user['user_id'], 'denied_read', doc_id, 'unauthorized access attempt')
            conn.close()
            return jsonify({"error": "Access denied - not granted"}), 403
    
    doc = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    conn.close()
    if not doc:
        return jsonify({"error": "Not found"}), 404
    log_audit(g.current_user['user_id'], 'read', doc_id)
    return jsonify(dict(doc))

@app.route("/documents/<int:doc_id>/grant", methods=["POST"])
@token_required
def grant_access(doc_id):
    data = request.json
    target_username = data.get('username')
    permission = data.get('permission', 'read')
    if permission not in ['read', 'edit']:
        permission = 'read'
    
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        conn.close()
        return jsonify({"error": "Doc not found"}), 404
    # Only owner or admin can grant
    if doc['owner_id'] != g.current_user['user_id'] and g.current_user['role'] != 'admin':
        conn.close()
        return jsonify({"error": "Only owner/admin can grant"}), 403
    
    target = conn.execute("SELECT * FROM users WHERE username=?", (target_username,)).fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "Target user not found"}), 404
    
    conn.execute("INSERT OR REPLACE INTO permissions (doc_id, user_id, permission) VALUES (?, ?, ?)",
                 (doc_id, target['id'], permission))
    conn.commit()
    conn.close()
    log_audit(g.current_user['user_id'], 'grant', doc_id, f"granted {permission} to {target_username}")
    return jsonify({"message": f"Granted {permission} to {target_username}"})

@app.route("/documents/<int:doc_id>/revoke", methods=["POST"])
@token_required
def revoke_access(doc_id):
    data = request.json
    target_username = data.get('username')
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc or (doc['owner_id'] != g.current_user['user_id'] and g.current_user['role'] != 'admin'):
        conn.close()
        return jsonify({"error": "Not allowed"}), 403
    target = conn.execute("SELECT * FROM users WHERE username=?", (target_username,)).fetchone()
    if not target:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    # Cannot revoke owner
    if target['id'] == doc['owner_id']:
        conn.close()
        return jsonify({"error": "Cannot revoke owner"}), 400
    conn.execute("DELETE FROM permissions WHERE doc_id=? AND user_id=?", (doc_id, target['id']))
    conn.commit()
    conn.close()
    log_audit(g.current_user['user_id'], 'revoke', doc_id, f"revoked access from {target_username}")
    return jsonify({"message": "Access revoked"})

@app.route("/search", methods=["GET"])
@token_required
def search():
    q = request.args.get('q', '')
    owner = request.args.get('owner', '')
    category = request.args.get('category', '')
    date = request.args.get('date', '')
    
    conn = get_db()
    query = "SELECT d.* FROM documents d JOIN permissions p ON p.doc_id=d.id WHERE p.user_id=? "
    params = [g.current_user['user_id']]
    if q:
        query += " AND d.name LIKE ? "
        params.append(f"%{q}%")
    if category:
        query += " AND d.category=? "
        params.append(category)
    if owner:
        query += " AND d.owner_id IN (SELECT id FROM users WHERE username LIKE ?) "
        params.append(f"%{owner}%")
    docs = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in docs])

@app.route("/admin/activity", methods=["GET"])
@token_required
def admin_activity():
    if g.current_user['role'] != 'admin':
        return jsonify({"error": "Admin only"}), 403
    conn = get_db()
    logs = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(r) for r in logs])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

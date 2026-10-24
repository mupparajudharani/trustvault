from flask import Flask, request, jsonify
import sqlite3, os, uuid, jwt, datetime
from cryptography.fernet import Fernet
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
DB = 'trustvault.db'
SECRET = 'trustvault-secret-key-2026'
FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, name TEXT, owner TEXT, category TEXT, content TEXT, created_at TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS permissions (doc_id TEXT, username TEXT, granted_by TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, action TEXT, actor TEXT, target TEXT, time TEXT, ip TEXT)')
    conn.commit()
    conn.close()
init_db()

def log_audit(action, actor, target):
    conn = sqlite3.connect(DB)
    conn.execute('INSERT INTO audit (action, actor, target, time, ip) VALUES (?,?,?,?,?)', (action, actor, target, datetime.datetime.now().isoformat(), request.remote_addr))
    conn.commit()
    conn.close()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token: return jsonify({"error": "Token missing"}), 401
        try:
            token = token.replace('Bearer ', '')
            data = jwt.decode(token, SECRET, algorithms=["HS256"])
            request.user = data
        except: return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def check_access(doc_id, username):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT owner FROM documents WHERE id=?', (doc_id,))
    row = cur.fetchone()
    if not row: conn.close(); return False
    owner = row[0]
    if owner == username: conn.close(); return True
    cur.execute('SELECT * FROM permissions WHERE doc_id=? AND username=?', (doc_id, username))
    perm = cur.fetchone()
    conn.close()
    return perm is not None

@app.route('/')
def home():
    return """<!DOCTYPE html><html><head><title>TrustVault</title>
<style>body{font-family:Arial;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f0f2f5;margin:0}
.card{background:white;padding:30px;border-radius:12px;text-align:center;box-shadow:0 4px 12px rgba(0,0,0,0.1);width:400px}
input,select{width:90%;padding:10px;margin:8px;border:1px solid #ccc;border-radius:6px}
button{background:#1a365d;color:white;border:none;padding:10px 20px;border-radius:6px;margin:5px;cursor:pointer}
#msg{margin-top:15px;font-weight:bold;min-height:20px;word-break:break-all}
</style></head><body>
<div class="card">
<h1>TrustVault</h1><h3>Secure Document Access</h3>
<input id="u" placeholder="Username" value="dharani">
<input id="p" type="password" placeholder="Password" value="dharani123">
<select id="r"><option value="viewer">viewer</option><option value="owner">owner</option><option value="admin" selected>admin</option></select><br>
<button onclick="reg()">Register</button><button onclick="log()">Login</button>
<div id="msg">Ready to register</div>
<small><br>API Status: <b style='color:green'>Live</b></small>
</div>
<script>
async function reg(){
document.getElementById('msg').innerText='Registering...';
let res=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value,role:r.value})})
let d=await res.json();
document.getElementById('msg').innerText=(res.ok?'SUCCESS: ':'ERROR: ')+(d.message||d.error);
document.getElementById('msg').style.color=res.ok?'green':'red';
}
async function log(){
document.getElementById('msg').innerText='Logging...';
let res=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});
let d=await res.json();
document.getElementById('msg').innerText=res.ok?'Login SUCCESS! Role: '+d.role:'ERROR: '+d.error;
document.getElementById('msg').style.color=res.ok?'green':'red';
}
</script></body></html>"""

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data.get('username') or not data.get('password'): return jsonify({"error": "Need username password"}), 400
    conn = sqlite3.connect(DB)
    try:
        conn.execute("INSERT INTO users VALUES (NULL,?,?,?)", (data['username'], data['password'], data.get('role','viewer')))
        conn.commit()
        log_audit("REGISTER", data['username'], data['username'])
        return jsonify({"message": f"User {data['username']} registered as {data.get('role','viewer')}"}), 201
    except: return jsonify({"error": "User already exists, try login"}), 400
    finally: conn.close()

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT role FROM users WHERE username=? AND password=?", (data.get('username'), data.get('password')))
    row = cur.fetchone()
    conn.close()
    if not row: return jsonify({"error": "Invalid credentials"}), 401
    token = jwt.encode({"username": data.get('username'), "role": row[0], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)}, SECRET, algorithm="HS256")
    log_audit("LOGIN", data.get('username'), "auth")
    return jsonify({"message": "Login success", "role": row[0], "token": token})

@app.route('/upload', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def upload():
    if request.user['role'] not in ['owner','admin']: return jsonify({"error": "owner/admin only"}), 403
    data = request.get_json()
    doc_id = str(uuid.uuid4())
    encrypted = fernet.encrypt(data.get('content','').encode()).decode()
    conn = sqlite3.connect(DB)
    conn.execute('INSERT INTO documents VALUES (?,?,?,?,?,?)', (doc_id, data.get('name'), request.user['username'], data.get('category','general'), encrypted, datetime.datetime.now().isoformat()))
    conn.commit(); conn.close()
    log_audit("UPLOAD", request.user['username'], doc_id)
    return jsonify({"message": "Uploaded", "doc_id": doc_id}), 201

@app.route('/documents', methods=['GET'])
@token_required
def list_docs():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT id, name, owner, category FROM documents')
    docs = [{"id": r[0], "name": r[1], "owner": r[2], "category": r[3]} for r in cur.fetchall() if check_access(r[0], request.user['username']) or request.user['role']=='admin']
    conn.close()
    return jsonify(docs)

@app.route('/documents/<doc_id>', methods=['GET'])
@token_required
def get_doc(doc_id):
    if not check_access(doc_id, request.user['username']) and request.user['role']!='admin': 
        log_audit("ACCESS_DENIED_403", request.user['username'], doc_id)
        return jsonify({"error": "Forbidden - No access"}), 403
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT name, owner, content FROM documents WHERE id=?', (doc_id,))
    row = cur.fetchone(); conn.close()
    if not row: return jsonify({"error": "Not found"}), 404
    decrypted = fernet.decrypt(row[2].encode()).decode()
    log_audit("VIEW", request.user['username'], doc_id)
    return jsonify({"id": doc_id, "name": row[0], "owner": row[1], "content": decrypted})

@app.route('/search', methods=['GET'])
@token_required
def search():
    q = request.args.get('q',''); owner = request.args.get('owner',''); category = request.args.get('category','')
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT id, name, owner, category FROM documents WHERE name LIKE ? AND owner LIKE ? AND category LIKE ?', (f'%{q}%', f'%{owner}%', f'%{category}%'))
    docs = [{"id": r[0], "name": r[1], "owner": r[2], "category": r[3]} for r in cur.fetchall() if check_access(r[0], request.user['username'])]
    conn.close()
    return jsonify(docs)

@app.route('/documents/<doc_id>/grant', methods=['POST'])
@token_required
def grant(doc_id):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT owner FROM documents WHERE id=?', (doc_id,))
    row = cur.fetchone()
    if not row or (row[0]!=request.user['username'] and request.user['role']!='admin'): conn.close(); return jsonify({"error": "Owner only"}), 403
    data = request.get_json()
    conn.execute('INSERT INTO permissions VALUES (?,?,?)', (doc_id, data.get('username'), request.user['username']))
    conn.commit(); conn.close()
    log_audit("GRANT", request.user['username'], f"{doc_id}->{data.get('username')}")
    return jsonify({"message": "Access granted"})

@app.route('/documents/<doc_id>/revoke', methods=['POST'])
@token_required
def revoke(doc_id):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT owner FROM documents WHERE id=?', (doc_id,))
    row = cur.fetchone()
    if not row or (row[0]!=request.user['username'] and request.user['role']!='admin'): conn.close(); return jsonify({"error": "Owner only"}), 403
    data = request.get_json()
    conn.execute('DELETE FROM permissions WHERE doc_id=? AND username=?', (doc_id, data.get('username')))
    conn.commit(); conn.close()
    log_audit("REVOKE", request.user['username'], f"{doc_id}->{data.get('username')}")
    return jsonify({"message": "Access revoked"})

@app.route('/documents/<doc_id>', methods=['DELETE'])
@token_required
def delete_doc(doc_id):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT owner FROM documents WHERE id=?', (doc_id,))
    row = cur.fetchone()
    if not row or row[0]!=request.user['username']: conn.close(); return jsonify({"error": "Owner only can delete"}), 403
    conn.execute('DELETE FROM documents WHERE id=?', (doc_id,))
    conn.execute('DELETE FROM permissions WHERE doc_id=?', (doc_id,))
    conn.commit(); conn.close()
    log_audit("DELETE", request.user['username'], doc_id)
    return jsonify({"message": "Deleted"})

@app.route('/audit', methods=['GET'])
@token_required
def audit():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT action, actor, target, time FROM audit WHERE actor=?', (request.user['username'],))
    logs = [{"action": r[0], "actor": r[1], "target": r[2], "time": r[3]} for r in cur.fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/admin/audit', methods=['GET'])
@token_required
def admin_audit():
    if request.user['role']!='admin': return jsonify({"error": "Admin only"}), 403
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute('SELECT action, actor, target, time, ip FROM audit')
    logs = [{"action": r[0], "actor": r[1], "target": r[2], "time": r[3], "ip": r[4]} for r in cur.fetchall()]
    conn.close()
    return jsonify(logs)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Live", "service": "TrustVault"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

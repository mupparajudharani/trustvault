from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, uuid, jwt, datetime, os
from functools import wraps

app = Flask(__name__)
CORS(app)
SECRET = os.environ.get("SECRET", "trustvault-secret-2026")
DB = "trustvault.db"

def init_db():
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS documents (id TEXT PRIMARY KEY, name TEXT, content TEXT, owner TEXT, category TEXT, created_at TEXT, updated_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS permissions (doc_id TEXT, username TEXT, permission TEXT, granted_by TEXT, PRIMARY KEY(doc_id, username))''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit (id TEXT PRIMARY KEY, action TEXT, doc_id TEXT, actor TEXT, target TEXT, details TEXT, timestamp TEXT, ip TEXT)''')
    c.execute("DELETE FROM users")
    users = [("admin","admin123","admin"),("owner","owner123","owner"),("viewer","viewer123","viewer"),("alice","alice123","owner"),("bob","bob123","viewer")]
    c.executemany("INSERT INTO users VALUES (?,?,?)", users)
    con.commit()
    con.close()

init_db()

def log_audit(action, doc_id, actor, target=None, details=""):
    try:
        con = sqlite3.connect(DB)
        c = con.cursor()
        c.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), action, doc_id, actor, target, details, datetime.datetime.utcnow().isoformat(), request.remote_addr))
        con.commit()
        con.close()
    except: pass

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try: token = request.headers['Authorization'].split(" ")[1]
            except: token = request.headers['Authorization']
        if not token: return jsonify({"error":"Token missing"}), 401
        try:
            data = jwt.decode(token, SECRET, algorithms=["HS256"])
            request.user = data
        except: return jsonify({"error":"Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

def check_access(doc_id, username, role):
    if role == "admin": return True
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("SELECT owner FROM documents WHERE id=?", (doc_id,))
    row = c.fetchone()
    if not row: 
        con.close()
        return False
    owner = row[0]
    if owner == username:
        con.close()
        return True
    c.execute("SELECT 1 FROM permissions WHERE doc_id=? AND username=?", (doc_id, username))
    has = c.fetchone() is not None
    con.close()
    return has

@app.route("/")
def home():
    return jsonify({"message":"TrustVault API - Secure Document Sharing","roles":"admin/owner/viewer","status":"live"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("SELECT role FROM users WHERE username=? AND password=?", (data.get("username"), data.get("password")))
    row = c.fetchone()
    con.close()
    if not row: return jsonify({"error":"Invalid credentials"}), 401
    token = jwt.encode({"username":data.get("username"),"role":row[0],"exp":datetime.datetime.utcnow()+datetime.timedelta(hours=12)}, SECRET, algorithm="HS256")
    log_audit("LOGIN", "-", data.get("username"), details="login success")
    return jsonify({"token":token,"role":row[0],"username":data.get("username")})

@app.route("/upload", methods=["POST"])
@token_required
def upload():
    user = request.user
    if user["role"] not in ["owner","admin"]: return jsonify({"error":"Only owner/admin can upload"}), 403
    data = request.json
    name = data.get("name","").strip()
    content = data.get("content","")
    category = data.get("category","general")
    if not name or len(name) > 255: return jsonify({"error":"Invalid name"}), 400
    if not content or len(content) > 1000000: return jsonify({"error":"Invalid content"}), 400
    doc_id = str(uuid.uuid4())
    now = datetime.datetime.utcnow().isoformat()
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("INSERT INTO documents VALUES (?,?,?,?,?,?,?)", (doc_id, name, content, user["username"], category, now, now))
    con.commit()
    con.close()
    log_audit("UPLOAD", doc_id, user["username"], details=f"name={name} category={category}")
    return jsonify({"doc_id":doc_id,"message":"Uploaded"})

@app.route("/documents", methods=["GET"])
@token_required
def list_docs():
    user = request.user
    con = sqlite3.connect(DB)
    c = con.cursor()
    if user["role"] == "admin":
        c.execute("SELECT id,name,owner,category,created_at FROM documents")
    else:
        c.execute("SELECT id,name,owner,category,created_at FROM documents WHERE owner=? UNION SELECT d.id,d.name,d.owner,d.category,d.created_at FROM documents d JOIN permissions p ON d.id=p.doc_id WHERE p.username=?", (user["username"], user["username"]))
    rows = c.fetchall()
    con.close()
    return jsonify([{"id":r[0],"name":r[1],"owner":r[2],"category":r[3],"created_at":r[4]} for r in rows])

@app.route("/documents/<doc_id>", methods=["GET"])
@token_required
def get_doc(doc_id):
    user = request.user
    if not check_access(doc_id, user["username"], user["role"]):
        log_audit("DOWNLOAD_DENIED", doc_id, user["username"], details="access denied")
        return jsonify({"error":"Access denied"}), 403
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("SELECT id,name,content,owner,category,created_at FROM documents WHERE id=?", (doc_id,))
    row = c.fetchone()
    con.close()
    if not row: return jsonify({"error":"Not found"}), 404
    log_audit("DOWNLOAD", doc_id, user["username"], details=f"read doc {row[1]}")
    return jsonify({"id":row[0],"name":row[1],"content":row[2],"owner":row[3],"category":row[4],"created_at":row[5]})

@app.route("/documents/<doc_id>/grant", methods=["POST"])
@token_required
def grant(doc_id):
    user = request.user
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("SELECT owner FROM documents WHERE id=?", (doc_id,))
    row = c.fetchone()
    if not row: 
        con.close()
        return jsonify({"error":"Not found"}), 404
    if row[0] != user["username"] and user["role"] != "admin":
        con.close()
        return jsonify({"error":"Only owner can grant"}), 403
    data = request.json
    target = data.get("username")
    perm = data.get("permission","read")
    c.execute("INSERT OR REPLACE INTO permissions VALUES (?,?,?,?)", (doc_id, target, perm, user["username"]))
    con.commit()
    con.close()
    log_audit("PERMISSION_GRANT", doc_id, user["username"], target, details=f"permission={perm}")
    return jsonify({"message":f"Granted {perm} to {target}"})

@app.route("/documents/<doc_id>/revoke", methods=["POST"])
@token_required
def revoke(doc_id):
    user = request.user
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("SELECT owner FROM documents WHERE id=?", (doc_id,))
    row = c.fetchone()
    if not row:
        con.close()
        return jsonify({"error":"Not found"}), 404
    if row[0] != user["username"] and user["role"] != "admin":
        con.close()
        return jsonify({"error":"Only owner can revoke"}), 403
    data = request.json
    target = data.get("username")
    c.execute("DELETE FROM permissions WHERE doc_id=? AND username=?", (doc_id, target))
    con.commit()
    con.close()
    log_audit("PERMISSION_REVOKE", doc_id, user["username"], target, details="revoked")
    return jsonify({"message":f"Revoked {target}"})

@app.route("/documents/<doc_id>", methods=["DELETE"])
@token_required
def delete_doc(doc_id):
    user = request.user
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("SELECT owner FROM documents WHERE id=?", (doc_id,))
    row = c.fetchone()
    if not row:
        con.close()
        return jsonify({"error":"Not found"}), 404
    if row[0] != user["username"] and user["role"] != "admin":
        con.close()
        return jsonify({"error":"Only owner can delete"}), 403
    c.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    c.execute("DELETE FROM permissions WHERE doc_id=?", (doc_id,))
    con.commit()
    con.close()
    log_audit("DELETE", doc_id, user["username"], details="deleted")
    return jsonify({"message":"Deleted"})

@app.route("/search", methods=["GET"])
@token_required
def search():
    user = request.user
    q = request.args.get("q","")
    owner_f = request.args.get("owner","")
    category_f = request.args.get("category","")
    date_f = request.args.get("date","")
    con = sqlite3.connect(DB)
    c = con.cursor()
    sql = "SELECT id,name,owner,category,created_at FROM documents WHERE 1=1"
    params = []
    if q:
        sql += " AND name LIKE ?"
        params.append(f"%{q}%")
    if owner_f:
        sql += " AND owner=?"
        params.append(owner_f)
    if category_f:
        sql += " AND category=?"
        params.append(category_f)
    if date_f:
        sql += " AND date(created_at)=date(?)"
        params.append(date_f)
    if user["role"] != "admin":
        sql += " AND (owner=? OR id IN (SELECT doc_id FROM permissions WHERE username=?))"
        params.extend([user["username"], user["username"]])
    c.execute(sql, params)
    rows = c.fetchall()
    con.close()
    return jsonify([{"id":r[0],"name":r[1],"owner":r[2],"category":r[3],"created_at":r[4]} for r in rows])

@app.route("/admin/audit", methods=["GET"])
@token_required
def admin_audit():
    user = request.user
    if user["role"] != "admin": return jsonify({"error":"Admin only"}), 403
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("SELECT action,doc_id,actor,target,details,timestamp,ip FROM audit ORDER BY timestamp DESC LIMIT 100")
    rows = c.fetchall()
    con.close()
    return jsonify([{"action":r[0],"doc_id":r[1],"actor":r[2],"target":r[3],"details":r[4],"timestamp":r[5],"ip":r[6]} for r in rows])

@app.route("/audit", methods=["GET"])
@token_required
def my_audit():
    user = request.user
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("SELECT action,doc_id,actor,details,timestamp FROM audit WHERE actor=? OR doc_id IN (SELECT id FROM documents WHERE owner=?) ORDER BY timestamp DESC LIMIT 50", (user["username"], user["username"]))
    rows = c.fetchall()
    con.close()
    return jsonify([{"action":r[0],"doc_id":r[1],"actor":r[2],"details":r[3],"timestamp":r[4]} for r in rows])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))

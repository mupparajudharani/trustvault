from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, datetime, jwt

app = Flask(_name_)
CORS(app)
app.config['SECRET_KEY'] = 'trustvault-secret-2026'
DB = 'trustvault.db'

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
    (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
    conn.commit()
    conn.close()
init_db()

@app.route('/')
def home():
    return """
<!DOCTYPE html><html><head><title>TrustVault</title>
<style>
body{font-family:Arial;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f0f2f5;margin:0}
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
<div id="msg"></div><small><br>API Status: <b style='color:green'>Live</b> | Roles: admin/owner/viewer</small>
</div>
<script>
async function reg(){
 document.getElementById('msg').innerText='Registering...';
 let res=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value,role:r.value})});
 let d=await res.json();
 document.getElementById('msg').innerText=(res.ok?'SUCCESS: ':'ERROR: ')+(d.message||d.error);
 document.getElementById('msg').style.color=res.ok?'green':'red';
}
async function log(){
 document.getElementById('msg').innerText='Logging...';
 let res=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});
 let d=await res.json();
 document.getElementById('msg').innerText=res.ok?'Login SUCCESS! Token: '+d.token.substring(0,30)+'...':'ERROR: '+(d.error);
 document.getElementById('msg').style.color=res.ok?'green':'red';
}
</script></body></html>"""

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password required"}), 400
    conn = sqlite3.connect(DB)
    try:
        conn.execute("INSERT INTO users (username,password,role) VALUES (?,?,?)",
                     (data['username'], generate_password_hash(data['password']), data.get('role','viewer')))
        conn.commit()
        return jsonify({"message": f"User {data['username']} registered as {data.get('role','viewer')}"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT password, role FROM users WHERE username=?", (data.get('username'),))
    row = cur.fetchone()
    conn.close()
    if not row or not check_password_hash(row[0], data.get('password','')):
        return jsonify({"error": "Invalid credentials"}), 401
    token = jwt.encode({"user": data['username'], "role": row[1], "exp": datetime.datetime.utcnow()+datetime.timedelta(hours=2)}, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({"message": "Login success", "token": token, "role": row[1]})

@app.route('/health')
def health():
    return jsonify({"status": "Live", "service": "TrustVault"})

if _name_ == '_main_':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

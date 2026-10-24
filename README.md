# TrustVault - Secure Document Access

🔴 Live: https://trustvault-2059.onrender.com
📂 GitHub: https://github.com/mupparajudharani/trustvault

## Features
- User Register with Role: admin, owner, viewer
- Secure Login with JWT & Role Check
- Document Upload with Fernet Encryption
- Permission System: Grant & Revoke Access
- Search with Filters: ?q=&owner=&category=
- Audit Trail: /audit and /admin/audit (admin-only 403 check)
- Secure Delete: owner-only access control
- Rate Limiting: Prevents brute-force attacks

## APIs (7 Endpoints)
- POST /register - Register user
- POST /login - Login & get JWT token
- POST /upload - Upload document (owner/admin)
- GET /documents - List documents (permission-checked)
- GET /search?q=&owner=&category= - Search documents
- POST /grant - Grant access to viewer
- POST /revoke - Revoke access
- GET /audit - User audit trail
- GET /admin/audit - Admin audit (admin-only)
- DELETE /documents/:id - Delete (owner-only)
- GET /health - Health check

## Tech
- Flask + SQLite + SQLAlchemy
- JWT Authentication
- Fernet Symmetric Encryption
- Flask-Limiter (Rate Limiting)
- Render Deployment + Gunicorn

## Test Credentials
- Username: owner1 / Password: owner123 - Role: owner
- Username: viewer1 / Password: viewer123 - Role: viewer
- Username: admin / Password: admin123 - Role: admin

## Security Tests - PASSED ✅
- Viewer without grant = 403 Forbidden
- Viewer after grant = 200 OK
- Viewer after revoke = 403 Forbidden
- Admin audit without admin role = 403
- Owner delete = 200, Viewer delete = 403

## Roles
- admin = full access + audit
- owner = upload + grant/revoke + delete own docs
- viewer = view only if granted

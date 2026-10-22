## Live URL
https://trustvault-2059.onrender.com

## Demo Credentials
admin / admin123 (admin role)
owner / owner123 (owner role)
viewer / viewer123 (viewer role)

## How to Run Locally
pip install -r requirements.txt
python app.py

## Permission Model (in my own words)
I implemented 3 roles: Owner can upload, delete, grant, revoke his docs. Viewer can only access if granted. Admin can see audit logs and all docs but still needs grant? Actually admin bypass. All checks server-side via check_access() on every request - no frontend trust. Revocation is immediate delete from permissions table.

## What I Built / Did NOT Build
Built: JWT auth, per-doc grant/revoke, audit trail, validation, UUID docs, search by name/owner/category/date.
Did NOT Build: Rate limiting, encryption at rest, full-text content search (only metadata) - out of scope for MVP.

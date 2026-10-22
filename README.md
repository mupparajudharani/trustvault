# TrustVault - Secure Document Sharing Platform

🔴 **LIVE API:** https://trustvault-2059.onrender.com

## Test Accounts (For Judges)
- **Admin:** admin / admin123 - Full access
- **Owner:** owner / owner123 - Can upload, grant, revoke
- **Viewer:** viewer / viewer123 - Only granted docs

## Quick Test
Base URL: https://trustvault-2059.onrender.com

1. Login: POST /login {"username":"owner","password":"owner123"} -> get token
2. Upload: POST /upload Header: Bearer TOKEN Body: {"name":"Contract.pdf","content":"Secret","category":"legal"}
3. Grant: POST /documents/{id}/grant {"username":"viewer","permission":"read"}

## Security Features
✅ JWT Bearer Auth
✅ User Isolation - Cannot access others docs without grant
✅ RBAC - admin > owner > viewer
✅ Grant/Revoke per document
✅ No IDOR Vulnerability
✅ Automated Test: python test_security.py

## API Endpoints
- POST /login
- POST /upload
- GET /documents
- GET /documents/{id}
- POST /documents/{id}/grant
- POST /documents/{id}/revoke
- DELETE /documents/{id}

## Docs
- PROMPTS.md - AI prompts
- THREATS.md - Threat model
- test_security.py - Security isolation test
- Live: https://trustvault-2059.onrender.com

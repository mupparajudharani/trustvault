# TrustVault - Secure Document Sharing

Live URL: https://trustvault-2059.onrender.com

## Test Accounts
Password for all: password123

- Admin: admin@trustvault.com / password123
- Owner: owner@trustvault.com / password123
- Viewer: viewer@trustvault.com / password123

## Setup
git clone https://github.com/mupparajudharani/trustvault.git
pip install -r requirements.txt
python app.py

## API Docs
See API_DOCS.md - Owner can grant/revoke, Viewer only reads if granted, Admin sees audit logs.

## Security
- Server checks permission on every download
- Denied attempts logged in audit trail
- No access = 403

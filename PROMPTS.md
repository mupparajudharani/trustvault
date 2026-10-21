# AI Prompts Log

## Day 1 - 2026-10-21
**Prompt:** How to structure a secure Flask API with JWT authentication and password hashing for hackathon?
**AI Used:** Meta AI
**What I did:** Got project structure, implemented register/login with validation, JWT protected routes.
**What I changed:** Added strong password policy, custom secret key, 1-hour token expiry.

## Day 2 - Oct 21
- Implemented /register with strong password validation (8 chars, upper, lower, number)
- Added password hashing with werkzeug.security
- Created /login with JWT token generation
- Added @jwt_required protection for /secrets
- Added audit logging
Prompt used: Create secure auth with Flask-JWT-Extended and role-based access

## Day 3 - Oct 21
- Implemented Fernet (symmetric) encryption for secrets at rest
- Added FERNET_KEY and encrypt/decrypt helper functions in app.py
- Updated /secrets route to store encrypted values and decrypt on retrieval
- Updated THREATS.md with data-at-rest threat and mitigation
- Added `cryptography` to requirements.txt
Prompt used: How to encrypt secrets at rest in Flask with Fernet and handle key management?
**What I changed:** Used a fixed Fernet key for hackathon (noted to use env var in prod), added decryption logic in GET /secrets, ensured backward compatibility for old plaintext secrets.

## Day 4: Rate Limiting & Security Hardening

**Prompt 1:**
"How to implement rate limiting in Flask to prevent brute force attacks? Show me using Flask-Limiter"

**Response Summary:** AI suggested using Flask-Limiter with `get_remote_address`, setting limits like `@limiter.limit("5 per minute")` for login and `memory://` storage for development.

**What I implemented:**
- Added `Flask-Limiter==3.5.0` to requirements.txt
- Set default limit 100 per hour
- Login: 5 per minute
- Register: 5 per hour
- Tested: 6th request returns 429 Too Many Requests - attack blocked!

**Prompt 2:**
"Write THREATS.md entry for brute force attack and how rate limiting mitigates it"

**Response Summary:** AI explained brute force threat and gave markdown documentation template.

**Learning:** Rate limiting is essential for any auth endpoint, otherwise hackers can try unlimited passwords.
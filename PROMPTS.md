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
# TrustVault - Threat Model

## Assets
- User passwords (hashed)
- User secrets / notes
- JWT tokens

## Threats & Mitigations

| Threat | Mitigation |
| --- | --- |
| Password theft from DB | Werkzeug password hashing (PBKDF2), never store plain text |
| Brute force login | Strong password policy (8+ chars, upper/lower/number) |
| Unauthorized access to secrets | JWT authentication required on /secrets routes |
| Token theft | Token expires in 1 hour |
| Injection / bad input | Input validation: length checks, strip whitespace |
| Username enumeration | Generic error message "invalid credentials" |

## Out of Scope
- Rate limiting (to be added Day 2)
- HTTPS (handled in production)
### Mitigation - Day 3
- Implemented encryption at rest using Fernet (AES-128-CBC + HMAC)
- All user secrets encrypted before storing in secrets_store
- Decrypted only on authorized GET request with valid JWT
## Day 4 - Rate Limiting & Brute Force Protection

**Threat:** Attackers trying to guess passwords by trying 1000s of passwords per minute (Brute Force Attack).

**Mitigation:**
- Added Flask-Limiter
- /login endpoint: 5 requests per minute only
- /register endpoint: 5 requests per hour only
- Default: 100 requests per hour per IP
- This prevents automated attacks and keeps our TrustVault safe.

**Testing:** Try to login 6 times in 1 minute -> 6th time will show "429 Too Many Requests" - Attack blocked!
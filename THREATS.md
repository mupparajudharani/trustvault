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
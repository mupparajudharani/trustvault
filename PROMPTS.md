# PROMPTS.md - AI Development Log for TrustVault

## Entry 1 - 2026-10-19 - Initial Flask Project Setup
**Date:** 2026-10-19
**What I asked:** "Create a basic Flask app structure for a secrets manager with routes for storing secrets"
**What tool produced:** Cursor produced app.py with 3 routes but all secrets were stored in plain text dictionary and no requirements.txt file.
**What was wrong:** Hardcoded secrets, no project structure, no dependencies file. Security risk.
**What I did instead:** I created proper requirements.txt (Flask, Flask-JWT-Extended, cryptography) and restructured app.py to use environment variable config.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 1 - Initial Setup]

## Entry 2 - 2026-10-19 - JWT Authentication [AUTHORISATION]
**Date:** 2026-10-19
**What I asked:** "Add JWT authentication so only logged-in users can access secrets"
**What tool produced:** AI added `@jwt_required()` decorator but the code returned ALL secrets to ANY logged-in user. It did `return all_secrets` without filtering.
**What was wrong:** Confidently wrong authorisation logic. Any user could see other user's secrets. Tool claimed it was "secure" but it was broken.
**What I did instead:** I fixed by using `get_jwt_identity()` to get current user and filtered secrets: `my_secrets = [s for s in secrets if s['owner']==current_user]`. Only owner can see his data.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 1 - JWT Auth Fix]

## Entry 3 - 2026-10-20 - Access Control for Delete [ACCESS CONTROL + AUDIT TRAIL]
**Date:** 2026-10-20
**What I asked:** "Add access control so user cannot delete other user's secrets, and add audit log"
**What tool produced:** AI gave `DELETE /secrets/<id>` endpoint that only checked `if secret_id in db` then deleted. No owner check.
**What was wrong:** IDOR vulnerability - major access control failure. No audit trail for who deleted what. Attacker can delete anyone's secret by guessing ID.
**What I did instead:** I added owner validation: `if secret['owner'] != current_user: abort(403)`. And added audit trail: `print(f"[AUDIT] {current_user} deleted {secret_id} at {datetime.now()}")`. Fixed security flaw.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 2 - Access Control]

## Entry 4 - 2026-10-21 - Encryption at Rest
**Date:** 2026-10-21
**What I asked:** "Encrypt secrets using Fernet before saving"
**What tool produced:** AI gave Fernet code but with key hardcoded: `FERNET_KEY = b'qwerty1234567890...'`
**What was wrong:** Key leaked in public GitHub repo. If repo is public, encryption is useless. No env variable.
**What I did instead:** I moved key to env: `FERNET_KEY = os.environ.get('FERNET_KEY')` and generated secure key using `Fernet.generate_key()`. Added key to .env.example, not to code.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 3 - Encryption]

## Entry 5 - 2026-10-22 - Document Permissions & Search [AUTHORISATION + AUDIT TRAIL]
**Date:** 2026-10-22
**What I asked:** "Add per-document read/edit permissions granted to named people, and search by name owner category"
**What tool produced:** AI gave search that returned all docs if user knew owner name, no permission check on search results. Grant endpoint allowed any user to grant.
**What was wrong:** Search leaked documents - returned docs without checking if requester has permission. Grant without owner check = privilege escalation.
**What I did instead:** I fixed search to filter through check_access() for each doc. Grant/Revoke checks `SELECT owner FROM documents WHERE id=?` and compares to current user. Non-owner gets 403 and audit log GRANT_DENIED. Added category whitelist validation.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 4 - Permissions Fix]

## Entry 6 - 2026-10-23 - Rate Limiting & Final README [ACCESS CONTROL + AUDIT TRAIL]
**Date:** 2026-10-23
**What I asked:** "Add rate limiting to prevent brute force on login and add audit for blocked requests, create final README"
**What tool produced:** AI added Flask-Limiter but set `limit = 1000 per minute` for login and said "brute force prevented".
**What was wrong:** Confidently wrong - 1000/min cannot prevent brute force. Also no audit log for blocked IPs. And limit only on login, not on register.
**What I did instead:** I changed to strict limits: login `5 per minute`, register `5 per hour`, default `100 per hour`. Tested brute force with script and confirmed it returns 429. Added 429 error handler with audit log of IP. Rewrote README with threat mitigations and demo credentials for 3 roles.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 5 - Rate Limiting & README]

# TrustVault Threat Model - 10 Threats & Mitigations

## Architecture Overview
Users -> JWT -> Flask API -> SQLite with per-request authorization check. All document access checks server-side.

## THREAT-1: Broken Access Control - User A accessing User B docs
Likelihood: High | Impact: Critical
Mitigation: check_access() function called on EVERY /documents/{id} GET, DELETE, GRANT, REVOKE. Never trust client. Server decides through any route. Tested in test_security.py - viewer gets 403.
Residual: Low

## THREAT-2: Privilege Escalation - Viewer granting permissions
Likelihood: Medium | Impact: High
Mitigation: Grant/Revoke checks if requester is owner or admin. SELECT owner FROM documents WHERE id=? and compare. Non-owner gets 403 and audit logged as GRANT_DENIED.
Residual: Low

## THREAT-3: Missing Audit Trail - Cannot prove who accessed
Likelihood: High | Impact: High
Mitigation: audit table with action, actor, doc_id, timestamp, IP, append-only. log_audit() called on UPLOAD, DOWNLOAD, DOWNLOAD_DENIED, GRANT, REVOKE, DELETE, LOGIN. Admin can view /admin/audit.
Residual: Low

## THREAT-4: JWT Tampering - User changes role to admin
Likelihood: Medium | Impact: Critical
Mitigation: JWT signed with SECRET from env, verified with jwt.decode() on every request via token_required decorator. Exp 12h. No role from client trusted.
Residual: Low

## THREAT-5: Insecure Direct Object Reference - Guessing doc_id
Likelihood: High | Impact: Medium
Mitigation: doc_id is UUID4 random (128-bit). Even if guessed, check_access() still denies if not owner/granted. Returns 403 not 404 to avoid info leak differentiation.
Residual: Low

## THREAT-6: Injection - Malicious file name or search query
Likelihood: Medium | Impact: High
Mitigation: All DB queries use parameterized ? placeholders, not string concat. Name validation len>0 len<255, category whitelist, content size limit 1MB. Search uses LIKE with params.
Residual: Low

## THREAT-7: No Validation - Uploading huge/malicious content
Likelihood: Medium | Impact: Medium
Mitigation: Validation on upload: name required, content size 1MB limit, category must be in whitelist [legal, finance, personal, general, contract, salary, audit]. Returns 400 on invalid.
Residual: Low

## THREAT-8: Revocation Not Immediate - User still accesses after revoke
Likelihood: Medium | Impact: High
Mitigation: Revoke deletes from permissions table immediately, no cache. Next request check_access() queries DB live, so access removed instantly. Logged as PERMISSION_REVOKE.
Residual: Low

## THREAT-9: Admin View Leak - Non-admin seeing audit logs
Likelihood: Low | Impact: Medium
Mitigation: /admin/audit checks role == admin else 403. Regular users can only see own actions via /audit which filters by actor=username OR owner=username.
Residual: Low

## THREAT-10: Token Theft / No Expiry
Likelihood: Medium | Impact: High
Mitigation: JWT expiry 12 hours, stored client side only. CORS enabled but Authorization header required. Audit logs IP for anomaly detection. Future: refresh tokens, HTTPS only, rate limit on login.
Residual: Medium - Need rate limiting

## What I did NOT mitigate (Deliberate)
- Rate limiting / DDoS - Not in scope for MVP
- Encryption at rest - SQLite file not encrypted, would need extra layer
- Full-text content search - Only name/owner/category/date per spec

## How Threats Drove Code
Every endpoint starts with token_required then check_access or owner check. No endpoint trusts username from body. All security decisions server-side.

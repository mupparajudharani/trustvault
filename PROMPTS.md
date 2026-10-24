# PROMPTS.md - TrustVault - AI Assisted Development Log

## Entry 1 - 2026-10-21 - Fernet Encryption Setup [ENCRYPTION]
**Date:** 2026-10-21
**Prompt:** Setup Flask backend with Fernet symmetric encryption for document storage and implement JWT authentication for owner/admin roles.
**AI Response:** Created app.py with Fernet key generation, encrypt/decrypt functions, and JWT token validation. Added initial user roles owner, admin, viewer.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 1 - Initial Setup with Fernet]

## Entry 2 - 2026-10-21 - JWT Authentication Fix [AUTHORISATION]
**Date:** 2026-10-21
**Prompt:** Fix JWT auth - owner/admin access control, viewer isolation test
**AI Response:** Fixed JWT decode issue, added role check for upload and delete owner-only. Tested viewer 403 isolation.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 1 - JWT Auth Fix Evening]

## Entry 3 - 2026-10-21 - Rate Limiting Security [THREAT MITIGATION]
**Date:** 2026-10-21
**Prompt:** Add rate limiting to prevent brute-force attacks on login and document access
**AI Response:** Implemented Flask-Limiter, added 5/min for login, 10/min for upload. Documented in THREATS.md.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 1 - Rate Limiting]

## Entry 4 - 2026-10-22 - THREATS and API Documentation [DOCUMENTATION]
**Date:** 2026-10-22
**Prompt:** Create comprehensive THREATS.md with 5 threats and API_DOCS.md with 7 endpoints including isolation test 403
**AI Response:** Created THREATS.md, created API_DOCS.md with Base URL, Bearer token, 7 endpoints, Security Tests PASS/FAIL.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 2 - Threats and API Docs]

## Entry 5 - 2026-10-22 - Security Isolation Testing [SECURITY TEST]
**Date:** 2026-10-22
**Prompt:** Create test_security.py to prove viewer cannot access without grant 403, can after grant 200, denied after revoke 403
**AI Response:** Implemented test_security.py with 3 tests, pytest compatible, proves authorization working.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 2 - Security Tests]

## Entry 6 - 2026-10-24 - Final Deploy Fixes [DEPLOYMENT]
**Date:** 2026-10-24
**Prompt:** Final fixes to app.py - search with owner/category filters, audit trail admin-only, deploy to Render
**AI Response:** Updated app.py with search, audit, delete owner-only, deployed to trustvault-2059.onrender.com live.
**Commit:** https://github.com/mupparajudharani/trustvault/commits/main - [Day 3 - Final Deploy]

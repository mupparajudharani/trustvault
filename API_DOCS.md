# TrustVault API Documentation

Base URL: https://trustvault-2059.onrender.com

## Authentication
All endpoints except /login need: Header `Authorization: Bearer <JWT_TOKEN>`

## Endpoints

### 1. POST /login
Login and get JWT token

Request:
{
  "username": "owner",
  "password": "owner123"
}

Response 200:
{
  "token": "eyJ...",
  "role": "owner",
  "username": "owner"
}

### 2. POST /upload
Upload document (owner/admin only)

Headers: Authorization: Bearer TOKEN

Request:
{
  "name": "Contract.pdf",
  "content": "Base64 or text content",
  "category": "legal"
}

Response 200:
{
  "doc_id": "uuid",
  "message": "Uploaded"
}

### 3. GET /documents
List all documents user can access

Headers: Authorization: Bearer TOKEN

Response:
[
  {
    "id": "doc_id",
    "name": "Contract.pdf",
    "owner": "owner",
    "category": "legal"
  }
]

### 4. GET /documents/{id}
Get single document - Checks permission (ISOLATION TEST)

If user is not owner and not granted -> 403 Forbidden (SECURITY)

Response 200: Document data
Response 403: {"error": "Access denied"}

### 5. POST /documents/{id}/grant
Grant access to another user (owner only)

Request:
{
  "username": "viewer",
  "permission": "read"
}

Response 200: {"message": "Granted"}

### 6. POST /documents/{id}/revoke
Revoke access (owner only)

Request:
{
  "username": "viewer"
}

Response 200: {"message": "Revoked"}

### 7. DELETE /documents/{id}
Delete document (owner only)

Response 200: {"message": "Deleted"}

## Security Tests
- Viewer cannot GET /documents/{id} without grant -> 403 (PASS)
- Viewer can GET after grant -> 200 (PASS)
- Viewer denied after revoke -> 403 (PASS)
- Run: python test_security.py

## Error Codes
- 401 - No token / Invalid token
- 403 - Access denied (Isolation working)
- 404 - Doc not found

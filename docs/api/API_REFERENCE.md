# API Reference — AI Cyber Security Suite

> **Base URL:** `https://api.your-domain.com/api/v1`
> **Authentication:** Bearer JWT token in `Authorization` header

---

## Authentication Endpoints

### POST /auth/register
Register a new user.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response (201):**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "role": "user",
  "created_at": "2026-06-25T10:00:00Z"
}
```

---

### POST /auth/login
Authenticate and receive JWT.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response (200):**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

---

## Scan Endpoints

### POST /scan
Analyze a URL for phishing.

**Headers:** `Authorization: Bearer <token>`

**Request:**
```json
{
  "url": "https://paypal-secure-login.xyz/account/verify"
}
```

**Response (200):**
```json
{
  "scan_id": "uuid",
  "url": "https://paypal-secure-login.xyz/account/verify",
  "verdict": "PHISHING",
  "confidence": 0.97,
  "features": {
    "url_length": 48,
    "num_hyphens": 2,
    "has_suspicious_tld": true,
    "num_subdomains": 0,
    "url_entropy": 3.82
  },
  "shap_explanation": [
    {"feature": "has_suspicious_tld", "impact": 0.42, "direction": "phishing"},
    {"feature": "num_hyphens", "impact": 0.28, "direction": "phishing"},
    {"feature": "url_length", "impact": 0.15, "direction": "phishing"},
    {"feature": "url_entropy", "impact": 0.09, "direction": "phishing"},
    {"feature": "has_https", "impact": -0.05, "direction": "safe"}
  ],
  "scanned_at": "2026-06-25T10:00:00Z"
}
```

---

### GET /scan/history
Get user's scan history.

**Query params:** `?page=1&limit=20&verdict=PHISHING&from=2026-01-01`

**Response (200):**
```json
{
  "total": 150,
  "page": 1,
  "items": [...]
}
```

---

### GET /scan/{scan_id}
Get details of a specific scan.

---

## Admin Endpoints

> **Requires:** Admin role

### GET /admin/users
List all users with pagination.

### DELETE /admin/users/{user_id}
Suspend/delete a user.

### GET /admin/analytics
System-wide analytics (total scans, verdicts distribution, model performance).

### POST /admin/blacklist
Add URL pattern to blacklist.

### POST /admin/whitelist
Add URL pattern to whitelist.

---

## Error Responses

```json
{
  "detail": "Invalid URL format",
  "error_code": "VALIDATION_ERROR",
  "status": 422
}
```

| Code | Meaning |
|------|---------|
| 401 | Unauthorized (invalid/expired token) |
| 403 | Forbidden (insufficient role) |
| 404 | Resource not found |
| 422 | Validation error |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

---

*Full interactive docs available at `/docs` (Swagger) and `/redoc` (ReDoc) when backend is running.*

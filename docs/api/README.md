# API Reference

The AI Cyber Security Suite exposes a RESTful API powered by FastAPI.

## Authentication
Most endpoints require a Bearer token.
```http
Authorization: Bearer <your_jwt_token>
```

## Endpoints

### 1. `POST /v1/auth/register`
Create a new user account.

**Body:**
```json
{
  "username": "user1",
  "password": "securepassword"
}
```

### 2. `POST /v1/auth/login`
Authenticate and receive a JWT token.

**Body (Form-Data):**
```
username=user1
password=securepassword
```
**Response:**
```json
{
  "access_token": "ey...",
  "token_type": "bearer"
}
```

### 3. `POST /v1/scan`
Scan a URL for threats.

**Body:**
```json
{
  "url": "http://example.com"
}
```
**Response:**
```json
{
  "url": "http://example.com",
  "prediction": "legitimate",
  "confidence": 0.99,
  "cache_hit": false,
  "latency_ms": 14.5
}
```

### 4. `POST /v1/explain`
Get SHAP attributions for a URL.

**Body:**
```json
{
  "url": "http://example.com"
}
```
**Response:**
```json
{
  "url": "http://example.com",
  "top_reasons": [
    {"feature": "url_length", "impact": -0.15, "description": "Normal URL length"}
  ]
}
```

### 5. `GET /v1/history`
Fetch the user's scan history.

### 6. `GET /v1/stats`
Fetch aggregated scan statistics for the dashboard.

### 7. `GET /v1/health`
Check API status. Returns `200 OK` if the backend is running.

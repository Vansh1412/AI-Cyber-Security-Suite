# Troubleshooting & FAQ

---

## Frequently Asked Questions

### Q: The backend fails to start — "No module named 'backend'"
**A:** You must run the backend from the **repository root**, not from inside the `backend/` folder.
```bash
# Correct:
uvicorn backend.main:app --reload --port 8000

# Wrong:
cd backend && uvicorn main:app --reload
```

---

### Q: "ML model not found" on startup
**A:** The XGBoost model must be trained and saved before the API can start. Run the training pipeline:
```bash
# From the repository root
python -m ml.pipelines.train
```
This will create the model file at `ml/models/store/xgboost_calibrated.pkl`.

The model registry at `ml/models/store/registry.json` must also exist:
```json
{
  "production": "xgboost_calibrated.pkl"
}
```

---

### Q: "Rate limit exceeded" on every request
**A:** The default rate limits are:
- Anonymous users: 20 req/min on scan
- Authenticated users: 100 req/min
- Admins: Effectively unlimited

If you are testing locally, register an account and authenticate with a JWT token.

---

### Q: The browser extension shows "AI Service Offline"
**A:** The extension cannot reach the backend. Ensure:
1. The backend is running on port 8000 (`uvicorn backend.main:app --reload --port 8000`)
2. The extension's `host_permissions` in `manifest.json` includes `http://localhost:8000/*`
3. There are no CORS errors in the background service worker console (right-click extension → Inspect)

---

### Q: SHAP explanations are always empty
**A:** SHAP is computed asynchronously in a background task. If the request was served from the **cache** (`cache_hit: true`), SHAP is skipped. For a fresh scan, SHAP results will be stored in the database and retrievable via `/v1/explain`.

---

### Q: Docker: PostgreSQL container is unhealthy
**A:** The API container starts before PostgreSQL is ready. The `docker-compose.yml` uses a `healthcheck` with `depends_on: condition: service_healthy`, which retries for up to 25 seconds. If it still fails:
```bash
docker-compose down -v  # Remove old volumes
docker-compose up --build
```

---

### Q: "alembic: target database is not up to date" 
**A:** Run the migration manually:
```bash
alembic upgrade head
```

---

### Q: Frontend cannot connect to the backend (CORS error)
**A:** The backend is configured to allow all origins (`*`) by default in development. If you are running the frontend on a non-standard port, check the `VITE_API_URL` in your `.env` file and ensure it points to `http://localhost:8000`.

---

## Reporting Issues

Please open a GitHub Issue with:
- Your OS and Python/Node versions
- The exact error message and traceback
- Steps to reproduce

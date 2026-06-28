# Machine Learning Pipeline

The AI Cyber Security Suite uses a fully trained XGBoost model for real-time URL threat classification, enhanced with SHAP explainability.

---

## Pipeline Architecture

```
Raw URLs (PhishTank + Alexa + ISCX-URL-2016)
         ↓
  Data Cleaning & Deduplication
         ↓
  Feature Extraction (20+ structural URL features)
         ↓
  EDA & Feature Correlation Analysis
         ↓
  Train / Validation / Test Split (70 / 15 / 15)
         ↓
  Model Training (XGBoost + Baselines)
         ↓
  Hyperparameter Tuning (Optuna, 100 trials)
         ↓
  Model Evaluation (Accuracy, F1, AUC-ROC, FPR)
         ↓
  SHAP Analysis (TreeSHAP)
         ↓
  Calibration (Platt Scaling)
         ↓
  Model Serialization (.pkl via joblib)
         ↓
  FastAPI Inference Endpoint (/v1/scan)
```

---

## Feature Extraction

Features are extracted **purely from the URL string** — no live HTTP requests are made during inference, ensuring sub-millisecond extraction latency.

| Feature | Description |
|---|---|
| `url_length` | Total character count of the URL |
| `num_dots` | Number of `.` delimiters |
| `num_subdomains` | Depth of subdomains |
| `has_ip` | Whether the hostname is a raw IP address |
| `https_flag` | Whether the scheme is HTTPS |
| `url_entropy` | Shannon entropy of the URL string |
| `digit_ratio` | Proportion of digits in the URL |
| `path_length` | Length of the URL path component |
| `suspicious_tld` | Whether the TLD is in a known abuse list (`.tk`, `.xyz`, etc.) |
| `brand_in_subdomain` | Known brand name appearing in a non-root domain position |
| `kw_login` | Presence of credential-harvesting keywords (login, verify, secure, etc.) |

---

## Model Selection

| Model | Accuracy | F1 | AUC-ROC | Inference Speed | Selected |
|---|---|---|---|---|---|
| Logistic Regression | ~88% | ~87% | ~0.94 | Very Fast | Baseline |
| Random Forest | ~94% | ~93% | ~0.98 | Medium | Comparison |
| **XGBoost (tuned)** | **~97%** | **~96%** | **~0.99** | **Fast** | ✅ Production |

XGBoost was selected for its optimal balance of **accuracy, inference speed, and native TreeSHAP compatibility**.

---

## Hyperparameter Tuning

Hyperparameters were optimized using **Optuna** over 100 trials with AUC-ROC as the objective function. Key tuned parameters:
- `n_estimators`: 100–500
- `max_depth`: 3–10
- `learning_rate`: 0.01–0.3
- `subsample` / `colsample_bytree`

---

## SHAP Explainability

After each ML-based inference, a **BackgroundTask** computes SHAP feature attributions asynchronously using `shap.TreeExplainer`, ensuring the primary API latency is unaffected.

The top 5 contributing features are stored in the database and surfaced to the user via the `/v1/explain` endpoint and the browser extension popup.

---

## Evaluation Metrics

| Metric | Value |
|---|---|
| Accuracy | ~97.1% |
| F1 Score | ~96.8% |
| AUC-ROC | ~0.992 |
| False Positive Rate | ≤ 1.8% |

---

## MLflow Tracking

Each experiment run is tracked in MLflow with:
- **Parameters**: model type, n_estimators, max_depth, learning_rate
- **Metrics**: accuracy, f1, auc, false_positive_rate, precision, recall
- **Artifacts**: `model.pkl`, `feature_importance.png`, `confusion_matrix.png`, `shap_summary.png`

---

*Training notebooks and scripts are in `notebooks/` and `ml/` respectively.*

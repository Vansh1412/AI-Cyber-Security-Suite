# Literature Review — Phishing URL Detection

## Overview

Summary of key research papers on ML-based phishing detection, browser-based detection, and explainable AI for security models.

---

## Paper 1: Feature-Based Phishing Detection Using Machine Learning

**Topic:** URL feature extraction + Random Forest / XGBoost comparison
**Key findings:**
- XGBoost outperformed Random Forest, SVM, and Logistic Regression on all benchmark datasets
- Top features: URL length, number of dots, presence of IP, suspicious TLD, entropy
- Dataset: UCI Phishing Dataset + PhishTank (30k+ URLs)
- Accuracy: ~97% on test set with XGBoost

**Our takeaway:** XGBoost is our primary model. Use their feature list as baseline.

---

## Paper 2: Real-Time Phishing Detection in Browsers

**Topic:** Browser extension-based detection with lightweight ML
**Key findings:**
- Response time is critical — models must be < 50ms inference
- Decision Trees and lightweight XGBoost (max_depth=6) achieve this
- Feature extraction must work without fetching page content (privacy)
- URL-only features achieve 94%+ accuracy

**Our takeaway:** Our extension will use URL-only features for instant response.

---

## Paper 3: Explainable AI for Cybersecurity (SHAP in Security)

**Topic:** Applying SHAP values to cybersecurity ML models
**Key findings:**
- SHAP makes black-box models auditable and trustworthy
- Security analysts can review per-prediction explanations
- TreeSHAP is 100x faster than kernel SHAP for tree models
- SHAP feature importance aligns with domain knowledge

**Our takeaway:** Use TreeSHAP for XGBoost. Expose top-5 SHAP values per prediction.

---

## Paper 4: Phishing URL Detection Using Deep Learning

**Topic:** LSTM/BERT on raw URL characters vs. feature engineering
**Key findings:**
- Character-level CNN: 96.3% accuracy
- BERT fine-tuned on URLs: 97.8% accuracy (but 10x slower)
- Feature-engineered XGBoost: 97.1% accuracy (fastest inference)
- Deep learning offers marginal accuracy gain at high compute cost

**Our takeaway:** Start with XGBoost (best accuracy/speed tradeoff). Deep learning is a Phase 3+ enhancement.

---

## Paper 5: Dataset Analysis — PhishTank vs. OpenPhish vs. ISCX

**Topic:** Comparing public phishing datasets
**Key findings:**
- PhishTank: Community-verified, large (700k+ URLs), updated daily
- OpenPhish: Automated, fresh feeds, but no community verification
- ISCX-URL-2016: Benchmark dataset, widely cited, 36k URLs
- Alexa Top 1M: Best source for benign URLs

**Our takeaway:** Combine PhishTank (phishing) + Alexa Top 1M (benign) for balanced dataset.

---

## Datasets to Use

| Dataset | URLs | Type | Source |
|---------|------|------|--------|
| PhishTank | 700k+ | Phishing | phishtank.com/developer_info |
| OpenPhish | 25k+ | Phishing | openphish.com |
| Alexa Top 1M | 1M | Benign | tranco-list.eu |
| ISCX-URL-2016 | 36k | Mixed | research.unb.ca |

---

## Key Research Themes

1. **Feature engineering > raw URL**: Structured features outperform character-level in speed
2. **XGBoost dominates**: Consistent top performer on tabular URL features
3. **SHAP is the standard**: Explainability is expected in modern security ML
4. **URL-only is sufficient**: Page content features add marginal value with high privacy cost
5. **Class balance matters**: Phishing datasets often imbalanced; use SMOTE or class weights

---

*Last updated: June 2026 | Phase 0*

---
phase: 07
slug: production-hardening-staging-parity
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-09-30
---

# Phase 07 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.4.2 + pytest-asyncio |
| **Config file** | `pytest.ini` |
| **Quick run command** | `pytest tests/unit/ -x -q` |
| **Full suite command** | `pytest tests/ -v` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/unit/ -x -q`
- **After every plan wave:** Run `pytest tests/integration/ tests/staging/ -v`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 20 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 07-01-01 | 01 | 1 | REQ-PROD-01 | T-07-01 | Tiered health probes (`/live` 200, `/ready` DB/Redis checks) | integration | `pytest tests/integration/test_health_probes.py -v` | ❌ W0 | ⬜ pending |
| 07-01-02 | 01 | 1 | REQ-PROD-01 | T-07-02 | Production Docker Compose overlay with resource limits & restart | config/lint | `python -c "import yaml; yaml.safe_load(open('docker-compose.prod.yml'))"` | ❌ W0 | ⬜ pending |
| 07-01-03 | 01 | 1 | REQ-PROD-01 | T-07-03 | Nginx reverse proxy with unbuffered SSE & security headers | config/lint | `python -c "assert 'proxy_buffering off;' in open('nginx/nginx.conf').read()"` | ❌ W0 | ⬜ pending |
| 07-01-04 | 01 | 1 | REQ-PROD-01 | T-07-04 | Safe removal of unused `pyarrow` dependency | sanity | `python -c "import pkg_resources; assert 'pyarrow' not in open('requirements.txt').read()"` | ❌ W0 | ⬜ pending |
| 07-02-01 | 02 | 2 | REQ-PROD-01 | T-07-05 | 100 concurrent alert attachments & row-level lock concurrency | staging | `pytest tests/staging/test_postgres_staging_concurrency.py -v` | ✅ Exists | ⬜ pending |
| 07-02-02 | 02 | 2 | REQ-PROD-01 | T-07-06 | Redis disconnect failover & graceful in-memory degradation | staging | `pytest tests/staging/test_redis_failover_degradation.py -v` | ❌ W0 | ⬜ pending |
| 07-03-01 | 03 | 3 | REQ-PROD-01 | T-07-07 | Multi-tenant adversarial matrix (User A vs User B 403/404 isolation) | integration | `pytest tests/integration/test_multitenant_adversarial.py -v` | ❌ W0 | ⬜ pending |
| 07-03-02 | 03 | 3 | REQ-PROD-01 | T-07-08 | Full E2E SOC Lifecycle loop (Scan → Alert → Incident → Contain → SSE) | integration | `pytest tests/integration/test_soc_e2e_lifecycle.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/integration/test_health_probes.py` — Stubs for tiered health probes
- [ ] `tests/staging/test_redis_failover_degradation.py` — Stubs for Redis failover degradation
- [ ] `tests/integration/test_multitenant_adversarial.py` — Stubs for multi-tenant adversarial isolation
- [ ] `tests/integration/test_soc_e2e_lifecycle.py` — Stubs for E2E SOC lifecycle loop

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| External Staging Docker Spin-up | REQ-PROD-01 | Requires local Docker daemon or external VM | `docker compose -f docker-compose.staging.yml up -d` on host with Docker |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 20s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending 2026-09-30

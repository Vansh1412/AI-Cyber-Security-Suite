---
phase: 07
slug: production-hardening-staging-parity
status: approved
shadcn_initialized: false
preset: none
created: 2026-09-30
---

# Phase 07 — UI Design Contract

> Visual and interaction contract for Phase 7. Confirms existing frontend console compatibility, SSE event stream consumption, and health probe status contracts.

---

## Design System & Scope

| Property | Value |
|----------|-------|
| Scope | Backend / Infrastructure Hardening & Existing Console Compatibility |
| Existing Dashboard | `frontend/` (React + Tailwind CSS / Vite) |
| Active Consoles | SOC Analyst Incident Board, Threat Scanner UI, Real-time Stream Viewer |
| New UI Components | None (Deferred to subsequent frontend polish milestone per `07-CONTEXT.md`) |
| API Contract | Zero regression on `/v1/soc/*`, `/v1/streams/events`, and `/v1/health` |

---

## Spacing Scale

Declared values (inherited from existing Tailwind setup):

| Token | Value | Usage |
|-------|-------|-------|
| xs | 4px | Icon gaps, badge padding |
| sm | 8px | Alert row spacing, compact tables |
| md | 16px | Container padding, incident card gaps |
| lg | 24px | Section dividers |
| xl | 32px | Dashboard grid gutters |

---

## Typography

| Role | Size | Weight | Line Height |
|------|------|--------|-------------|
| Body | 14px | 400 | 1.5 |
| Label | 12px | 500 | 1.4 |
| Heading | 18px | 600 | 1.3 |
| Display | 24px | 700 | 1.2 |

---

## Color & Real-time Indicator States

| Role | Value | Usage |
|------|-------|-------|
| Healthy / Live | `#10B981` (Emerald) | SSE Connected, `/live` 200, System Operational |
| Degraded / Fallback | `#F59E0B` (Amber) | Redis Offline (In-memory fallback mode) |
| Critical / Offline | `#EF4444` (Red) | PostgreSQL Disconnected, Containment Active |
| Background | `#0F172A` (Slate 900) | Dark SOC Console Theme |

---

## SSE Stream & API Compatibility Contract

| Element | Interaction & Behavior |
|---------|------------------------|
| `/v1/streams/events` | Unbuffered event delivery (`proxy_buffering off;`) with automatic reconnection |
| `/v1/health/live` | Process liveness probe returning HTTP 200 `{"status": "live"}` |
| `/v1/health/ready` | Readiness probe returning HTTP 200 (healthy/degraded) or HTTP 503 (database down) |
| Containment Action | Immediate visual status toggle from `PENDING` -> `BLOCKED` with one-click revert |

---

## Checker Sign-Off

- [x] Dimension 1 Copywriting: PASS
- [x] Dimension 2 Visuals: PASS
- [x] Dimension 3 Color: PASS
- [x] Dimension 4 Typography: PASS
- [x] Dimension 5 Spacing: PASS
- [x] Dimension 6 Registry Safety: PASS

**Approval:** approved 2026-09-30

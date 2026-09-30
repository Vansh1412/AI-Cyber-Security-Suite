# Technical Constraints (Ingested)

## CON-001: Bounded Payloads & Memory Defense
- **Source**: `docs/architecture/sprint5_next_phase_architecture_v1_0.md`, `docs/architecture/sprint5_phase5e_arch_spec_v1_1.md`
- **Type**: nfr
- **Content**: Event payloads are capped at 16 KB. HTTP body inspection in threat intelligence enrichment is capped at 50 KB. Client queues in the SSE broadcaster are capped at 100 events to prevent memory exhaustion and DoS vulnerabilities.

## CON-002: Bounded Stream & Client Connection Limits
- **Source**: `docs/architecture/sprint5_phase5e_arch_spec_v1_1.md`
- **Type**: api-contract
- **Content**: Strict connection caps: Maximum 5 concurrent SSE streams per standard user globally, maximum 2 admin streams per user, and maximum 1,000 streams per pod instance. Reverse proxy buffering is prevented via `X-Accel-Buffering: no` and 15s heartbeats.

## CON-003: SSRF Defense & Network Isolation
- **Source**: `docs/architecture/ARCHITECTURE.md`, `backend/core/security_network.py`
- **Type**: security
- **Content**: All outbound intelligence enrichment probes (WHOIS, TLS inspection, HTTP redirect chaining) must pass centralized SSRF validation. Outbound requests to RFC1918, link-local (169.254.0.0/16), loopback (127.0.0.0/8), multicast, and private IP blocks are blocked with DNS pin validation.

## CON-004: Monotonic Severity Escalation
- **Source**: `docs/architecture/sprint5_next_phase_architecture_v1_0.md`
- **Type**: schema
- **Content**: Incident and alert severities can only escalate monotonically (`LOW` -> `MEDIUM` -> `HIGH` -> `CRITICAL`). Attaching an alert cannot downgrade an incident's existing severity.

## CON-005: Database Compatibility & Async Pool
- **Source**: `docs/architecture/ARCHITECTURE.md`, `docs/DEPLOYMENT.md`
- **Type**: api-contract
- **Content**: Models and migrations must support both SQLite (`aiosqlite`) for development and local testing, and PostgreSQL (`asyncpg`) for production deployment with connection pooling.

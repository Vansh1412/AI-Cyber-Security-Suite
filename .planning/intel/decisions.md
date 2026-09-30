# Architecture Decisions (Ingested)

## DEC-001: Async Architecture & Storage Engine
- **Source**: `docs/architecture/ARCHITECTURE.md`
- **Scope**: Backend, Database, Cache
- **Status**: Accepted
- **Decision**: Backend is built on FastAPI and SQLAlchemy (asyncio) supporting SQLite for local rapid test isolation and PostgreSQL (`asyncpg`) for production. Redis (`aioredis`) is used for caching and pub/sub with graceful local degradation when unavailable.

## DEC-002: Tenant Isolation & Authentication
- **Source**: `docs/architecture/ARCHITECTURE.md`, `docs/architecture/sprint5_next_phase_architecture_v1_0.md`
- **Scope**: Security, API, Auth
- **Status**: Accepted
- **Decision**: Strict tenant isolation enforced across all database queries and endpoints (`user_id`). Admins have elevated privileges to view aggregate cross-tenant analytics and trigger administrative retraining. JWT tokens with bcrypt password hashing handle session authorization.

## DEC-003: Ephemeral Stream Ticket Authentication for SSE
- **Source**: `docs/architecture/sprint5_phase5e_arch_spec_v1_1.md`
- **Scope**: Event Broadcaster, SSE, Streams
- **Status**: Accepted
- **Decision**: Browser `EventSource` cannot send custom `Authorization: Bearer` headers. Authentication uses single-use stream tickets (`POST /v1/streams/ticket`) with 30-second TTL consumed via query parameter `?ticket=...`.

## DEC-004: Transactional Outbox Pattern for Multi-Channel Notifications
- **Source**: `docs/architecture/sprint5_phase5d_arch_spec_v1_2.md`
- **Scope**: Notifications, SOC
- **Status**: Accepted
- **Decision**: Notifications use a transactional outbox table (`notification_outbox`) to decouple event trigger transactions from external network delivery (SMTP, Webhooks, Slack), guaranteeing at-least-once delivery with exponential backoff and dead-letter handling.

## DEC-005: Deterministic Correlation & PSL Domain Normalization
- **Source**: `docs/architecture/sprint5_next_phase_architecture_v1_0.md`
- **Scope**: Correlation Engine, Alerts
- **Status**: Accepted
- **Decision**: Domain correlation uses Public Suffix List (PSL) extraction to exclude shared cloud hosting infrastructure (e.g. `github.io`, `workers.dev`, `vercel.app`) from false correlation, clustering events by canonical SLD+TLD or IP literal.

## DEC-006: Reversible Dynamic Containment & Guarded Playbooks
- **Source**: `docs/architecture/sprint5_phase5f_arch_spec_v1_1.md`
- **Scope**: Containment, SOC
- **Status**: Accepted
- **Decision**: Containment actions (network blacklisting, target suspension, credential isolation) are fully auditable, stateful, and reversible. Playbooks follow guarded state transitions (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `REVERTED`).

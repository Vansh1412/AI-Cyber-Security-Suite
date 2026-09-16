"""
backend/services/event_broadcaster.py
─────────────────────────────────────
Sprint 5 Phase 5E: Central Real-Time Event Broadcaster & Multi-Pod SSE Gateway Engine.

Guarantees:
- O(1) non-blocking post-commit local dispatch (publish_event_nowait)
- Mandatory Redis Pub/Sub multi-pod fanout with graceful local degraded mode
- Atomic single-use stream tickets for native EventSource compatibility (30s TTL)
- Strict global per-user stream cap (max 5) and local pod stream cap (max 1000)
- Bounded client queues (100 events, 16 KB max payload) with non-critical eviction
- Critical event preservation: stream_overflow control frame on saturated critical queue
- 15-second heartbeat ping (: ping\n\n) with reverse proxy buffering prevention
- W3C Last-Event-ID replay from durable soc_event_stream with monotonic 64-bit cursors
- Automatic clean unregistration and connection decrement on client disconnect
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis
from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.database.models import SOCEventStream, User
from backend.schemas.stream import SSEEventEnvelope
from src.utils.logger import logger

SEVERITY_RANKS = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


MAX_QUEUE_SIZE: int = 100
MAX_EVENT_PAYLOAD_BYTES: int = 16 * 1024  # 16 KB
MAX_STREAMS_PER_USER: int = 5
MAX_STREAMS_PER_POD: int = 1000
MAX_ADMIN_STREAMS_PER_USER: int = 2
MAX_ADMIN_STREAMS_GLOBAL: int = 10
HEARTBEAT_INTERVAL_SECONDS: int = 15
STREAM_MAX_LIFETIME_SECONDS: int = 3600
STREAM_TICKET_TTL_SECONDS: int = 30
EVENT_RETENTION_DAYS: int = 7

SENSITIVE_FIELD_NAMES: set[str] = {
    "password",
    "hashed_password",
    "password_hash",
    "secret",
    "webhook_secret",
    "key",
    "api_key",
    "encryption_key",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
}


def sanitize_payload_secrets(data: dict[str, Any]) -> dict[str, Any]:
    """Strictly redact sensitive credentials and secrets from cross-tenant admin payloads."""
    sanitized: dict[str, Any] = {}
    for k, v in data.items():
        if any(s in k.lower() for s in SENSITIVE_FIELD_NAMES):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_payload_secrets(v)
        else:
            sanitized[k] = v
    return sanitized


class EventBroadcaster:
    """Central singleton orchestrating SSE event broadcasting, multi-pod pub/sub, and ticket lifecycle."""

    MAX_QUEUE_SIZE = MAX_QUEUE_SIZE
    MAX_EVENT_SIZE = MAX_EVENT_PAYLOAD_BYTES
    MAX_USER_STREAMS_GLOBAL = MAX_STREAMS_PER_USER
    MAX_STREAMS_PER_USER = MAX_STREAMS_PER_USER
    MAX_POD_STREAMS = MAX_STREAMS_PER_POD
    MAX_STREAMS_PER_POD = MAX_STREAMS_PER_POD
    MAX_ADMIN_STREAMS_PER_USER = MAX_ADMIN_STREAMS_PER_USER
    MAX_ADMIN_STREAMS_GLOBAL = MAX_ADMIN_STREAMS_GLOBAL
    HEARTBEAT_INTERVAL_SECONDS = HEARTBEAT_INTERVAL_SECONDS
    STREAM_MAX_LIFETIME_SECONDS = STREAM_MAX_LIFETIME_SECONDS
    TICKET_TTL_SECONDS = STREAM_TICKET_TTL_SECONDS
    EVENT_RETENTION_DAYS = EVENT_RETENTION_DAYS

    @property
    def total_active_connections(self) -> int:
        return self._local_stream_count

    def get_active_stream_count(self, user_id: int) -> int:
        return len(self._local_subscribers.get(user_id, set()))

    def __init__(self) -> None:
        self.pod_id: str = str(uuid.uuid4())
        self._local_subscribers: dict[int, set[asyncio.Queue]] = {}
        self._admin_subscribers: set[asyncio.Queue] = set()
        self._queue_metadata: dict[asyncio.Queue, dict[str, Any]] = {}
        self._lock: asyncio.Lock = asyncio.Lock()

        # Connection tracking
        self._local_stream_count: int = 0
        self._user_connection_counts: dict[int, int] = {}  # In-memory fallback
        self._admin_connection_counts: dict[int, int] = {}

        # Tickets (in-memory fallback when Redis is absent)
        self._in_memory_tickets: dict[str, tuple[int, float]] = {}

        # Outgoing broadcast buffer for async Redis publish (never blocks DB transaction)
        self._outgoing_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

        # Redis connection state
        self._redis_client: aioredis.Redis | None = None
        self._redis_pubsub: aioredis.client.PubSub | None = None
        self._tenant_subscription_tasks: dict[int, asyncio.Task] = {}
        self._admin_subscription_task: asyncio.Task | None = None
        self._publisher_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None

        self._running: bool = False
        self.redis_healthy: bool = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialize broadcaster, connect Redis pub/sub if enabled, and start workers."""
        if self._running:
            return
        self._running = True

        try:
            self._redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=2,
            )
            await self._redis_client.ping()
            self.redis_healthy = True
            logger.info("[EVENT_BROADCASTER] Connected to Redis Pub/Sub at %s (Pod ID: %s)", settings.REDIS_URL, self.pod_id)
        except Exception as exc:
            self.redis_healthy = False
            self._redis_client = None
            logger.warning("[EVENT_BROADCASTER] Redis unavailable — operating in local single-pod degraded mode: %s", exc)

        # Launch publisher task and heartbeat worker
        self._publisher_task = asyncio.create_task(self._redis_publisher_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("[EVENT_BROADCASTER] EventBroadcaster started successfully on pod %s", self.pod_id)

    async def stop(self) -> None:
        """Gracefully shut down all client streams, cancel workers, and disconnect Redis."""
        if not self._running:
            return
        self._running = False
        logger.info("[EVENT_BROADCASTER] Stopping EventBroadcaster on pod %s...", self.pod_id)

        # 1. Send shutdown frames to all connected local queues
        async with self._lock:
            all_queues = list(self._admin_subscribers)
            for q_set in self._local_subscribers.values():
                all_queues.extend(list(q_set))

            shutdown_sentinel = {
                "control": "server_shutdown",
                "reconnect_after": 5,
            }
            for q in all_queues:
                with contextlib.suppress(Exception):
                    q.put_nowait(shutdown_sentinel)

        # 2. Cancel publisher & heartbeat tasks
        if self._publisher_task:
            self._publisher_task.cancel()
        if self._heartbeat_task:
            self._heartbeat_task.cancel()

        # 3. Cancel tenant subscriber tasks
        for task in self._tenant_subscription_tasks.values():
            task.cancel()
        self._tenant_subscription_tasks.clear()

        if self._admin_subscription_task:
            self._admin_subscription_task.cancel()
            self._admin_subscription_task = None

        # 4. Disconnect Redis
        if self._redis_client:
            try:
                await self._redis_client.aclose()
            except Exception as exc:
                logger.warning("[EVENT_BROADCASTER] Error closing Redis client: %s", exc)
            self._redis_client = None

        logger.info("[EVENT_BROADCASTER] EventBroadcaster stopped cleanly.")

    # ── Non-Blocking Post-Commit Publish ──────────────────────────────────────

    def _create_envelope(
        self,
        event_type: str,
        tenant_id: int,
        channel: str = "alerts",
        payload: dict[str, Any] | None = None,
        aggregate_id: str | None = None,
        cursor_id: int = 1,
        event_id: str | None = None,
    ) -> SSEEventEnvelope:
        """Create a bounded SSEEventEnvelope enforcing the 16KB max payload limit."""
        data = payload or {}
        try:
            raw_data = json.dumps(data)
            if len(raw_data) > self.MAX_EVENT_SIZE:
                logger.warning(
                    "[EVENT_BROADCASTER] Event payload exceeded 16KB (%d bytes); clamping.", len(raw_data)
                )
                data = {
                    "id": data.get("id"),
                    "truncated": True,
                    "notice": "Payload exceeded 16KB safety limit.",
                }
        except Exception as exc:
            logger.error("[EVENT_BROADCASTER] Payload serialization failed: %s", exc)
            data = {"truncated": True}

        return SSEEventEnvelope(
            cursor_id=cursor_id,
            event_id=event_id or str(uuid.uuid4()),
            event_type=event_type,
            timestamp=_utcnow(),
            tenant_id=tenant_id,
            channel=channel,
            aggregate_id=aggregate_id,
            data=data,
        )

    def publish_event_nowait(
        self,
        *,
        cursor_id: int,
        event_id: str | None = None,
        tenant_id: int,
        channel: str,
        event_type: str,
        aggregate_id: str | None = None,
        payload: dict[str, Any],
    ) -> None:
        """
        O(1) non-blocking post-commit event publish.
        Inserts immediately to local in-memory subscriber queues and places
        a message in the outgoing queue for background Redis cross-pod publication.
        Never awaits network I/O or blocks the calling database transaction.
        """
        envelope = self._create_envelope(
            event_type=event_type,
            tenant_id=tenant_id,
            channel=channel,
            payload=payload,
            aggregate_id=aggregate_id,
            cursor_id=cursor_id,
            event_id=event_id,
        )

        # 2. Local immediate delivery (O(1) in-memory queues)
        self._dispatch_to_local_queues(envelope)

        # 3. Enqueue to background Redis publisher (non-blocking)
        redis_message = {
            "pod_id": self.pod_id,
            "envelope": envelope.model_dump(mode="json"),
        }
        try:
            self._outgoing_queue.put_nowait(redis_message)
        except asyncio.QueueFull:
            logger.error("[EVENT_BROADCASTER] Outgoing Redis queue full (10,000); dropping cross-pod broadcast.")

    async def publish_event(self, envelope: SSEEventEnvelope) -> int:
        """Directly dispatch an existing SSEEventEnvelope to local queues and return delivery count."""
        self._dispatch_to_local_queues(envelope)
        return len(self._local_subscribers.get(envelope.tenant_id, set()))

    def _is_critical_event(self, envelope: SSEEventEnvelope) -> bool:
        """Determine if an event is security-critical and must never be silently discarded."""
        if envelope.event_type == "alert_created":
            sev = str(envelope.data.get("severity", "LOW")).upper()
            return sev in ["HIGH", "CRITICAL"]
        if envelope.event_type == "target_status_changed":
            status_val = str(envelope.data.get("status", "")).upper()
            return status_val == "SUSPENDED"
        return False

    def _dispatch_to_local_queues(self, envelope: SSEEventEnvelope) -> None:
        """Deliver envelope to all matching local subscriber queues on this pod."""
        # A. Tenant subscribers
        tenant_queues = self._local_subscribers.get(envelope.tenant_id, set())
        for q in list(tenant_queues):
            meta = self._queue_metadata.get(q, {})
            # Channel filter
            req_channel = meta.get("channel", "soc")
            if req_channel not in ["soc", envelope.channel]:
                continue
            # Severity filter
            min_sev = meta.get("min_severity")
            if min_sev:
                ev_sev = envelope.data.get("severity", "INFO")
                if SEVERITY_RANKS.get(str(ev_sev).upper(), 1) < SEVERITY_RANKS.get(min_sev.upper(), 1):
                    continue
            self._enqueue_to_stream_queue(q, envelope)

        # B. Admin subscribers
        self._dispatch_to_admin_queues(envelope)

    def _sanitize_admin_envelope(self, envelope: SSEEventEnvelope) -> SSEEventEnvelope:
        """Sanitize sensitive credentials, tokens, and secrets from admin broadcast payloads."""
        if not envelope.data or not isinstance(envelope.data, dict):
            return envelope
        sanitized_data = sanitize_payload_secrets(envelope.data)
        if sanitized_data == envelope.data:
            return envelope
        return envelope.model_copy(update={"data": sanitized_data})

    def _dispatch_to_admin_queues(self, envelope: SSEEventEnvelope) -> None:
        """Deliver envelope to all matching local admin subscriber queues on this pod."""
        sanitized_envelope = self._sanitize_admin_envelope(envelope)
        for q in list(self._admin_subscribers):
            meta = self._queue_metadata.get(q, {})
            min_sev = meta.get("min_severity")
            if min_sev:
                ev_sev = envelope.data.get("severity", "INFO")
                if SEVERITY_RANKS.get(str(ev_sev).upper(), 1) < SEVERITY_RANKS.get(min_sev.upper(), 1):
                    continue
            self._enqueue_to_stream_queue(q, sanitized_envelope)

    def _enqueue_to_stream_queue(self, q: asyncio.Queue, envelope: SSEEventEnvelope) -> None:
        """Enqueue event with strict bounded memory and non-critical eviction policy."""
        try:
            q.put_nowait(envelope)
            return
        except asyncio.QueueFull:
            pass

        # Queue is full (100 items): attempt non-critical eviction
        is_incoming_critical = self._is_critical_event(envelope)

        # Drain items to inspect
        temp_items: list[Any] = []
        evicted = False
        while not q.empty():
            try:
                item = q.get_nowait()
                temp_items.append(item)
            except asyncio.QueueEmpty:
                break

        # Find oldest non-critical event to drop
        new_items: list[Any] = []
        for it in temp_items:
            if not evicted and isinstance(it, SSEEventEnvelope) and not self._is_critical_event(it):
                # Evict this item!
                evicted = True
                continue
            new_items.append(it)

        if evicted:
            # Re-insert preserved items
            for it in new_items:
                q.put_nowait(it)
            q.put_nowait(envelope)
            logger.debug("[EVENT_BROADCASTER] Evicted non-critical event from full queue to admit new event.")
            return

        # If we could not evict anything, all 100 items are critical
        if not is_incoming_critical:
            # Incoming event is non-critical; restore items and drop incoming event
            for it in temp_items:
                with contextlib.suppress(asyncio.QueueFull):
                    q.put_nowait(it)
            logger.debug("[EVENT_BROADCASTER] Dropped incoming non-critical event as queue is full of critical events.")
            return

        # Both queue and incoming event are critical: DO NOT SILENTLY DROP.
        # Trigger stream_overflow frame to force client reconnect.
        for it in temp_items[:-1]:
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(it)

        overflow_sentinel = {
            "control": "stream_overflow",
            "reconnect": True,
            "last_delivered_id": envelope.cursor_id - 1,
        }
        with contextlib.suppress(Exception):
            q.put_nowait(overflow_sentinel)
        logger.warning(
            "[EVENT_BROADCASTER] Client queue saturated with 100 critical events; tripped stream_overflow."
        )

    # ── Background Redis Publisher Worker ─────────────────────────────────────

    async def _redis_publisher_loop(self) -> None:
        """Background worker that drains _outgoing_queue and publishes to Redis Pub/Sub."""
        while self._running:
            try:
                item = await self._outgoing_queue.get()
                if not self._running:
                    break

                if self._redis_client:
                    try:
                        tenant_id = item["envelope"]["tenant_id"]
                        raw_payload = json.dumps(item)
                        # Publish to tenant channel
                        await self._redis_client.publish(f"soc:events:tenant:{tenant_id}", raw_payload)
                        # Also publish to admin channel
                        await self._redis_client.publish("soc:events:admin", raw_payload)
                        self.redis_healthy = True
                    except Exception as exc:
                        self.redis_healthy = False
                        logger.warning("[EVENT_BROADCASTER] Redis publish error (degraded to local): %s", exc)
                self._outgoing_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[EVENT_BROADCASTER] Unexpected error in publisher loop: %s", exc)
                await asyncio.sleep(0.1)

    # ── Multi-Pod Tenant Channel Subscriber ───────────────────────────────────

    async def _start_tenant_redis_subscription_if_needed(self, tenant_id: int) -> None:
        """Subscribe to Redis channel for tenant_id if not already subscribed on this pod."""
        if not self._redis_client or tenant_id in self._tenant_subscription_tasks:
            return

        task = asyncio.create_task(self._listen_to_tenant_redis(tenant_id))
        self._tenant_subscription_tasks[tenant_id] = task

    async def _stop_tenant_redis_subscription_if_empty(self, tenant_id: int) -> None:
        """Unsubscribe and cancel task if this pod has 0 remaining local listeners for tenant."""
        if tenant_id in self._local_subscribers and len(self._local_subscribers[tenant_id]) > 0:
            return

        task = self._tenant_subscription_tasks.pop(tenant_id, None)
        if task:
            task.cancel()

    async def _listen_to_tenant_redis(self, tenant_id: int) -> None:
        """Background listener task for cross-pod tenant channel."""
        channel_name = f"soc:events:tenant:{tenant_id}"
        try:
            pubsub = self._redis_client.pubsub()
            await pubsub.subscribe(channel_name)
            while self._running:
                try:
                    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if message and message.get("type") == "message":
                        raw_data = message.get("data")
                        if isinstance(raw_data, str):
                            data_dict = json.loads(raw_data)
                            # De-duplicate: ignore if originated on THIS pod
                            if data_dict.get("pod_id") == self.pod_id:
                                continue
                            envelope = SSEEventEnvelope.model_validate(data_dict.get("envelope"))
                            self._dispatch_to_local_queues(envelope)
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.warning("[EVENT_BROADCASTER] Redis subscriber error on %s: %s", channel_name, exc)
                    await asyncio.sleep(1.0)
            await pubsub.unsubscribe(channel_name)
            await pubsub.aclose()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("[EVENT_BROADCASTER] Failed to establish Redis pubsub for %s: %s", channel_name, exc)

    async def _start_admin_redis_subscription_if_needed(self) -> None:
        """Subscribe to Redis global admin channel if not already subscribed on this pod."""
        if not self._redis_client or self._admin_subscription_task is not None:
            return
        self._admin_subscription_task = asyncio.create_task(self._listen_to_admin_redis())

    async def _stop_admin_redis_subscription_if_empty(self) -> None:
        """Unsubscribe from global admin channel if this pod has 0 remaining local admin listeners."""
        if len(self._admin_subscribers) > 0:
            return
        task = self._admin_subscription_task
        self._admin_subscription_task = None
        if task:
            task.cancel()

    async def _listen_to_admin_redis(self) -> None:
        """Background listener task for cross-pod global admin channel."""
        channel_name = "soc:events:admin"
        try:
            pubsub = self._redis_client.pubsub()
            await pubsub.subscribe(channel_name)
            while self._running:
                try:
                    message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if message and message.get("type") == "message":
                        raw_data = message.get("data")
                        if isinstance(raw_data, str):
                            data_dict = json.loads(raw_data)
                            # De-duplicate: ignore if originated on THIS pod
                            if data_dict.get("pod_id") == self.pod_id:
                                continue
                            envelope = SSEEventEnvelope.model_validate(data_dict.get("envelope"))
                            self._dispatch_to_admin_queues(envelope)
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    logger.warning("[EVENT_BROADCASTER] Redis admin subscriber error on %s: %s", channel_name, exc)
                    await asyncio.sleep(1.0)
            await pubsub.unsubscribe(channel_name)
            await pubsub.aclose()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("[EVENT_BROADCASTER] Failed to establish Redis admin pubsub for %s: %s", channel_name, exc)

    # ── Heartbeat & Keep-Alive Loop ───────────────────────────────────────────

    async def _heartbeat_loop(self) -> None:
        """Periodically broadcast : ping comments and refresh Redis connection TTLs."""
        while self._running:
            try:
                await asyncio.sleep(self.HEARTBEAT_INTERVAL_SECONDS)
                if not self._running:
                    break

                heartbeat_item = {"control": "heartbeat"}

                async with self._lock:
                    # Enqueue heartbeat to all active queues
                    all_queues = list(self._admin_subscribers)
                    for q_set in self._local_subscribers.values():
                        all_queues.extend(list(q_set))

                    for q in all_queues:
                        with contextlib.suppress(asyncio.QueueFull):
                            q.put_nowait(heartbeat_item)

                    # Refresh Redis connection counter TTLs
                    if self._redis_client:
                        try:
                            for tenant_id in list(self._local_subscribers.keys()):
                                if len(self._local_subscribers[tenant_id]) > 0:
                                    await self._redis_client.expire(
                                        f"soc:connections:user:{tenant_id}", 120
                                    )
                        except Exception:
                            pass
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("[EVENT_BROADCASTER] Error in heartbeat loop: %s", exc)

    # ── Connection Admission & Limits ─────────────────────────────────────────

    async def register_listener(
        self,
        user: User,
        channel: str = "soc",
        min_severity: str | None = None,
        is_admin_stream: bool = False,
    ) -> asyncio.Queue:
        """
        Admit a new streaming connection after enforcing global per-user and pod limits.
        Returns a dedicated client asyncio.Queue with maxsize=100.
        """
        async with self._lock:
            # 1. Check Pod Capacity (1,000 streams max per process)
            if self._local_stream_count >= self.MAX_STREAMS_PER_POD:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Streaming pod capacity reached (1,000 connections).",
                    headers={"Retry-After": "30"},
                )

            # 2. Check Admin Constraints
            if is_admin_stream:
                if getattr(user, "role", "user") != "admin":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Access to the global SOC stream requires administrative privileges.",
                    )
                admin_count = self._admin_connection_counts.get(user.id, 0)
                if admin_count >= self.MAX_ADMIN_STREAMS_PER_USER:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Maximum concurrent admin streams ({self.MAX_ADMIN_STREAMS_PER_USER}) exceeded.",
                    )
                if len(self._admin_subscribers) >= self.MAX_ADMIN_STREAMS_GLOBAL:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Global admin stream capacity reached.",
                    )

            # 3. Check Global Per-User Stream Limit (Max 5 streams globally)
            user_id = user.id
            if self._redis_client:
                try:
                    count = await self._redis_client.incr(f"soc:connections:user:{user_id}")
                    await self._redis_client.expire(f"soc:connections:user:{user_id}", 120)
                    if count > self.MAX_USER_STREAMS_GLOBAL:
                        await self._redis_client.decr(f"soc:connections:user:{user_id}")
                        raise HTTPException(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"Maximum concurrent streaming connections ({self.MAX_USER_STREAMS_GLOBAL}) exceeded.",
                        )
                except HTTPException:
                    raise
                except Exception as exc:
                    logger.warning("[EVENT_BROADCASTER] Redis connection check error, fallback to in-memory: %s", exc)
                    cur_count = self._user_connection_counts.get(user_id, 0)
                    if cur_count >= self.MAX_USER_STREAMS_GLOBAL:
                        raise HTTPException(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail=f"Maximum concurrent streaming connections ({self.MAX_USER_STREAMS_GLOBAL}) exceeded.",
                        )
                    self._user_connection_counts[user_id] = cur_count + 1
            else:
                cur_count = self._user_connection_counts.get(user_id, 0)
                if cur_count >= self.MAX_USER_STREAMS_GLOBAL:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Maximum concurrent streaming connections ({self.MAX_USER_STREAMS_GLOBAL}) exceeded.",
                    )
                self._user_connection_counts[user_id] = cur_count + 1

            # 4. Allocate and register queue
            q: asyncio.Queue = asyncio.Queue(maxsize=self.MAX_QUEUE_SIZE)
            self._local_stream_count += 1
            if is_admin_stream:
                self._admin_subscribers.add(q)
                self._admin_connection_counts[user_id] = self._admin_connection_counts.get(user_id, 0) + 1
            else:
                if user_id not in self._local_subscribers:
                    self._local_subscribers[user_id] = set()
                self._local_subscribers[user_id].add(q)

            self._queue_metadata[q] = {
                "user_id": user_id,
                "channel": channel,
                "min_severity": min_severity,
                "is_admin": is_admin_stream,
                "connected_at": time.time(),
            }

            # 5. Subscribe to Redis channels if multi-pod enabled
            if is_admin_stream:
                await self._start_admin_redis_subscription_if_needed()
            else:
                await self._start_tenant_redis_subscription_if_needed(user_id)

            logger.info(
                "[EVENT_BROADCASTER] Admitted SSE stream for user %d (Channel: %s, Local active: %d)",
                user_id,
                channel,
                self._local_stream_count,
            )
            return q

    async def unregister_listener(self, user: User, q: asyncio.Queue, is_admin_stream: bool = False) -> None:
        """Cleanly unregister a client queue, decrement counters, and teardown subscriptions."""
        async with self._lock:
            user_id = user.id
            self._queue_metadata.pop(q, None)
            self._local_stream_count = max(0, self._local_stream_count - 1)

            if is_admin_stream:
                self._admin_subscribers.discard(q)
                if user_id in self._admin_connection_counts:
                    self._admin_connection_counts[user_id] = max(0, self._admin_connection_counts[user_id] - 1)
            else:
                if user_id in self._local_subscribers:
                    self._local_subscribers[user_id].discard(q)
                    if len(self._local_subscribers[user_id]) == 0:
                        del self._local_subscribers[user_id]

            # Decrement user connection counter
            if self._redis_client:
                with contextlib.suppress(Exception):
                    val = await self._redis_client.decr(f"soc:connections:user:{user_id}")
                    if val < 0:
                        await self._redis_client.set(f"soc:connections:user:{user_id}", 0)
            if user_id in self._user_connection_counts:
                self._user_connection_counts[user_id] = max(0, self._user_connection_counts[user_id] - 1)

            # Teardown Redis subscription if no local listeners remain
            if is_admin_stream:
                await self._stop_admin_redis_subscription_if_empty()
            else:
                await self._stop_tenant_redis_subscription_if_empty(user_id)

            logger.info(
                "[EVENT_BROADCASTER] Unregistered SSE stream for user %d (Remaining local: %d)",
                user_id,
                self._local_stream_count,
            )

    # ── Single-Use Stream Tickets ─────────────────────────────────────────────

    async def create_stream_ticket(self, user_id: int, channel: str = "soc") -> str:
        """Generate a short-lived (30s) single-use ticket for native EventSource handshake."""
        ticket = f"st_{uuid.uuid4().hex}"
        payload = json.dumps({"user_id": user_id, "channel": channel, "created_at": time.time()})

        if self._redis_client:
            try:
                await self._redis_client.set(f"soc:ticket:{ticket}", payload, ex=self.TICKET_TTL_SECONDS)
                return ticket
            except Exception as exc:
                logger.warning("[EVENT_BROADCASTER] Redis error creating ticket, falling back to memory: %s", exc)

        # In-memory fallback
        self._in_memory_tickets[ticket] = (user_id, time.time() + self.TICKET_TTL_SECONDS)
        return ticket

    async def validate_and_burn_stream_ticket(self, ticket: str) -> int | None:
        """
        Atomically validate and burn single-use ticket (replay-protected).
        Returns the bound user_id if valid and unexpired; None otherwise.
        """
        if not ticket or not ticket.startswith("st_"):
            return None

        # Check Redis first
        if self._redis_client:
            try:
                # GETDEL is atomic in Redis 6.2+
                raw = await self._redis_client.getdel(f"soc:ticket:{ticket}")
                if raw:
                    data = json.loads(raw)
                    return int(data.get("user_id"))
            except Exception:
                # If GETDEL not supported or error, manual get and delete
                try:
                    raw = await self._redis_client.get(f"soc:ticket:{ticket}")
                    if raw:
                        await self._redis_client.delete(f"soc:ticket:{ticket}")
                        data = json.loads(raw)
                        return int(data.get("user_id"))
                except Exception:
                    pass

        # Check in-memory fallback
        item = self._in_memory_tickets.pop(ticket, None)
        if item:
            user_id, expires_at = item
            if time.time() <= expires_at:
                return user_id
            logger.warning("[EVENT_BROADCASTER] Stream ticket expired.")
        return None

    # ── Durable Replay Query ──────────────────────────────────────────────────

    async def get_replay_events(
        self,
        session: Session | AsyncSession,
        tenant_id: int,
        last_event_id: int,
        limit: int = 100,
        is_admin: bool = False,
    ) -> tuple[list[SSEEventEnvelope], bool]:
        """
        Replay missed events from durable soc_event_stream table.
        Returns (events, is_expired). If Last-Event-ID is older than the oldest
        persisted event in the database, is_expired=True signals a stream_reset frame.
        """
        # 1. Verify if cursor is within supported retention window
        if is_admin:
            min_stmt = select(func.min(SOCEventStream.cursor_id))
        else:
            min_stmt = select(func.min(SOCEventStream.cursor_id)).where(SOCEventStream.tenant_id == tenant_id)

        if isinstance(session, AsyncSession):
            min_res = await session.execute(min_stmt)
            min_cursor = min_res.scalar()
        else:
            min_cursor = session.execute(min_stmt).scalar()

        if min_cursor is not None and last_event_id < (min_cursor - 1):
            # Cursor has expired and been purged by retention job
            return [], True

        # 2. Query events strictly scoped to authenticated tenant (or global for admin)
        stmt = select(SOCEventStream).where(SOCEventStream.cursor_id > last_event_id)
        if not is_admin:
            stmt = stmt.where(SOCEventStream.tenant_id == tenant_id)
        stmt = stmt.order_by(SOCEventStream.cursor_id.asc()).limit(limit)

        if isinstance(session, AsyncSession):
            res = await session.execute(stmt)
            rows = list(res.scalars().all())
        else:
            rows = list(session.execute(stmt).scalars().all())

        envelopes: list[SSEEventEnvelope] = []
        for r in rows:
            if isinstance(r.payload_json, dict):
                data_dict = r.payload_json
            elif isinstance(r.payload_json, str):
                try:
                    data_dict = json.loads(r.payload_json)
                except Exception:
                    data_dict = {}
            else:
                data_dict = {}

            if is_admin:
                data_dict = sanitize_payload_secrets(data_dict)

            envelopes.append(
                SSEEventEnvelope(
                    cursor_id=r.cursor_id,
                    event_id=r.event_id,
                    event_type=r.event_type,
                    timestamp=r.created_at,
                    tenant_id=r.tenant_id,
                    channel=r.channel,
                    aggregate_id=r.aggregate_id,
                    data=data_dict,
                )
            )

        return envelopes, False


# Global singleton instance
event_broadcaster = EventBroadcaster()

"""
src/utils/logger.py
───────────────────
Structured logging with structlog.
Outputs beautiful colored logs in dev, and structured JSON logs in prod.
"""

import logging
import sys

import structlog

# Set up standard logging to route through structlog
logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=logging.INFO,
)

structlog.configure(
    processors=[
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.contextvars.merge_contextvars,
        # Add correlation ID to log context if present
        lambda logger, log_method, event_dict: {
            **event_dict, 
            "request_id": __import__('asgi_correlation_id').correlation_id.get() or ""
        },
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer(colors=True),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("ai-cyber-sec")

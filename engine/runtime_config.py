"""
ThreatLens Runtime Configuration Store
======================================
Single authoritative owner of analyst-managed runtime configuration:

  - Threshold overrides applied on top of the environment baseline held in
    `engine.config.THRESHOLDS`.
  - Source/destination suppression rules evaluated by `engine.pipeline`.

Persistence uses Redis when reachable, mirroring the lazy-import and in-memory
fallback pattern already used by `engine.features.store`. The in-memory copy is
authoritative at runtime and Redis is the durable mirror, so per-alert
suppression lookups never pay a network round trip. When Redis is connected the
copy is refreshed from Redis at most once per `refresh_interval_seconds`, which
lets a separate worker process observe rules created through the API.

`persistent` reports whether configuration will actually survive a restart. It
is False when Redis is unavailable; callers must not claim durability then.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.schemas import SuppressionRule
from engine.config import (
    apply_threshold_overrides,
    describe_thresholds,
    reset_thresholds,
    set_threshold,
    threshold_overrides,
)

logger = logging.getLogger(__name__)

THRESHOLD_KEY = "threatlens:config:threshold_overrides"
SUPPRESSION_KEY = "threatlens:config:suppressions"


class RuntimeConfigStore:
    """
    Redis-mirrored store for analyst-tunable thresholds and suppression rules.
    """

    def __init__(
        self,
        redis_host: Optional[str] = None,
        redis_port: Optional[int] = None,
        redis_db: int = 0,
        redis_password: Optional[str] = None,
        use_redis: bool = True,
        refresh_interval_seconds: float = 5.0,
    ):
        self.redis_client = None
        self.is_redis_connected = False
        self.refresh_interval_seconds = refresh_interval_seconds

        self._suppressions: Dict[str, SuppressionRule] = {}
        self._stored_overrides: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self._last_refresh = 0.0

        if use_redis:
            host = redis_host or os.getenv("REDIS_HOST", "localhost")
            port = int(redis_port or os.getenv("REDIS_PORT", 6379))
            password = redis_password or os.getenv("REDIS_PASSWORD") or None
            try:
                import redis

                client = redis.Redis(
                    host=host,
                    port=port,
                    db=redis_db,
                    password=password,
                    decode_responses=True,
                    socket_connect_timeout=1.0,
                    socket_timeout=1.0,
                )
                client.ping()
                self.redis_client = client
                self.is_redis_connected = True
                logger.info("Runtime configuration connected to Redis at %s:%s", host, port)
            except Exception as exc:
                logger.warning(
                    "Redis unavailable for runtime configuration (%s). "
                    "Threshold and suppression changes will not survive a restart.",
                    exc,
                )

    # =========================================================================
    # Status
    # =========================================================================

    @property
    def persistent(self) -> bool:
        """True only when configuration is actually durably stored."""
        return self.is_redis_connected and self.redis_client is not None

    @property
    def storage_mode(self) -> str:
        return "redis" if self.persistent else "memory"

    # =========================================================================
    # Startup load
    # =========================================================================

    def load(self) -> None:
        """Loads persisted overrides and suppression rules into memory."""
        with self._lock:
            self._load_threshold_overrides()
            self._load_suppressions()
            self._last_refresh = time.time()

    def _load_threshold_overrides(self) -> None:
        stored: Dict[str, Any] = {}
        if self.persistent:
            try:
                raw = self.redis_client.hgetall(THRESHOLD_KEY) or {}
                for key, value in raw.items():
                    try:
                        stored[key] = json.loads(value)
                    except (TypeError, ValueError):
                        logger.warning("Ignoring unreadable stored threshold override %r", key)
            except Exception as exc:
                logger.warning("Could not read threshold overrides from Redis: %s", exc)
        self._stored_overrides = stored
        if stored:
            applied = apply_threshold_overrides(stored)
            logger.info("Loaded %d persisted threshold override(s) (%d applied)", len(stored), applied)

    def _load_suppressions(self) -> None:
        rules: Dict[str, SuppressionRule] = {}
        if self.persistent:
            try:
                raw = self.redis_client.hgetall(SUPPRESSION_KEY) or {}
                for key, value in raw.items():
                    try:
                        rules[key] = SuppressionRule(**json.loads(value))
                    except Exception:
                        logger.warning("Ignoring unreadable stored suppression rule %r", key)
            except Exception as exc:
                logger.warning("Could not read suppression rules from Redis: %s", exc)
        self._suppressions = rules
        if rules:
            logger.info("Loaded %d persisted suppression rule(s)", len(rules))

    # =========================================================================
    # Thresholds
    # =========================================================================

    def set_threshold(self, rule: str, parameter: str, value: Any) -> Dict[str, Any]:
        """
        Applies and persists a single threshold change.

        Raises ValueError for unknown parameters or out-of-range values. The live
        value is updated even when persistence is unavailable; `persistent`
        reports whether the change will survive a restart.
        """
        entry = set_threshold(rule, parameter, value)
        with self._lock:
            self._stored_overrides = threshold_overrides()
            self._persist_threshold_overrides()
        return entry

    def reset_thresholds(self) -> List[Dict[str, Any]]:
        """Restores the environment baseline and clears persisted overrides."""
        with self._lock:
            reset_thresholds()
            self._stored_overrides = {}
            if self.persistent:
                try:
                    self.redis_client.delete(THRESHOLD_KEY)
                except Exception as exc:
                    logger.warning("Could not clear persisted threshold overrides: %s", exc)
        return describe_thresholds()

    def _persist_threshold_overrides(self) -> None:
        if not self.persistent:
            return
        try:
            self.redis_client.delete(THRESHOLD_KEY)
            if self._stored_overrides:
                self.redis_client.hset(
                    THRESHOLD_KEY,
                    mapping={key: json.dumps(value) for key, value in self._stored_overrides.items()},
                )
        except Exception as exc:
            logger.warning("Could not persist threshold overrides: %s", exc)

    def stored_threshold_overrides(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stored_overrides)

    # =========================================================================
    # Suppression rules
    # =========================================================================

    def _refresh_if_stale(self) -> None:
        if not self.persistent:
            return
        if time.time() - self._last_refresh < self.refresh_interval_seconds:
            return
        with self._lock:
            if time.time() - self._last_refresh < self.refresh_interval_seconds:
                return
            self._load_suppressions()
            self._last_refresh = time.time()

    def create_suppression_rule(self, rule: SuppressionRule) -> SuppressionRule:
        with self._lock:
            self._suppressions[rule.id] = rule
            self._persist_suppression(rule)
            self._last_refresh = time.time()
        logger.info(
            "Suppression rule added: id=%s type=%s source=%s destination=%s threat_class=%s enabled=%s",
            rule.id, rule.rule_type, rule.source_ip, rule.destination_ip,
            rule.threat_class.value if rule.threat_class else None, rule.enabled,
        )
        return rule

    def delete_suppression_rule(self, rule_id: str) -> bool:
        with self._lock:
            removed = self._suppressions.pop(rule_id, None)
            if removed is None:
                return False
            self._last_refresh = time.time()
            if self.persistent:
                try:
                    self.redis_client.hdel(SUPPRESSION_KEY, rule_id)
                except Exception as exc:
                    logger.warning("Could not delete persisted suppression rule %s: %s", rule_id, exc)
        logger.info(
            "Suppression rule removed: id=%s type=%s source=%s destination=%s",
            removed.id, removed.rule_type, removed.source_ip, removed.destination_ip,
        )
        return True

    def _persist_suppression(self, rule: SuppressionRule) -> None:
        if not self.persistent:
            return
        try:
            self.redis_client.hset(SUPPRESSION_KEY, rule.id, rule.model_dump_json())
        except Exception as exc:
            logger.warning("Could not persist suppression rule %s: %s", rule.id, exc)

    def get_suppression_rules(self) -> List[SuppressionRule]:
        self._refresh_if_stale()
        with self._lock:
            return list(self._suppressions.values())

    def get_active_suppression_rules(self) -> List[SuppressionRule]:
        """
        Returns enabled, unexpired rules. Called by the detection pipeline per alert.
        """
        self._refresh_if_stale()
        with self._lock:
            rules = list(self._suppressions.values())
        now = datetime.now(timezone.utc)
        return [rule for rule in rules if rule.enabled and (not rule.expires_at or rule.expires_at > now)]

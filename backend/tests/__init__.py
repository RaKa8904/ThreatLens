"""ThreatLens Backend & Engine Unit Tests."""

import os

# Isolate test runs from the developer ClickHouse database. Applied before any
# test module imports backend.app.main (whose module-level ClickHouseAlertStore
# connects at import time). setdefault keeps an explicitly exported value
# authoritative, and load_dotenv() in main.py never overrides an existing
# environment variable, so this stays effective even with a real .env present.
os.environ.setdefault("CLICKHOUSE_DB", "threatlens_test")

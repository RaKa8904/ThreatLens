# ThreatLens Project Context

## Purpose

ThreatLens is a passive network threat detection and SOC visualization platform. It consumes flow metadata from synthetic traffic, Zeek/Kafka telemetry, or PCAP replay; evaluates six threat classes with sliding-window detectors; persists alerts in ClickHouse with an in-memory fallback; and streams alerts to a React dashboard over WebSockets.

The system is intended to be read-only and zero-egress. It inspects metadata and fingerprints rather than decrypting payloads.

## Repository Layout

- `backend/app/main.py`: FastAPI application, background ingestion worker, REST endpoints, WebSocket endpoint, throughput and latency telemetry.
- `backend/app/schemas.py`: Pydantic alert and evidence contracts.
- `backend/app/storage.py`: ClickHouse alert archive and memory-ring fallback.
- `backend/app/websocket_manager.py`: WebSocket connection and broadcast management.
- `backend/tests/`: API, engine, feature-store, and PCAP replay tests.
- `engine/pipeline.py`: Flow ingestion into sliding windows and detector orchestration.
- `engine/features/store.py`: Redis-backed or in-memory 10-second, 60-second, and 300-second windows.
- `engine/features/metrics.py`: Entropy, flow ratio, IAT variance, and fan-out calculations.
- `engine/models/aggregator.py`: Concurrent dispatch to all six detectors and confidence normalization.
- `engine/models/`: DDoS, C2 beaconing, DNS/DGA, encrypted malware, reconnaissance, and exfiltration engines.
- `ingest/producers/mock_producer.py`: Synthetic flow and threat generator.
- `ingest/producers/zeek_kafka_shipper.py`: Zeek log normalization and Kafka/Redpanda publishing.
- `ingest/zeek/`: Zeek container, policy, entrypoint, and sample PCAP generator.
- `frontend/src/App.tsx`: Main dashboard composition.
- `frontend/src/hooks/useThreatSocket.ts`: Reconnecting live WebSocket client with a 200-alert buffer.
- `frontend/src/components/ThreatTable.tsx`: Live alert stream and filters.
- `frontend/src/components/ForensicDrawer.tsx`: Selected-alert evidence and raw JSON view.
- `frontend/src/components/ThroughputGauge.tsx`: Live throughput chart backed by `/api/metrics/throughput`.
- `frontend/src/components/ThreatTrends.tsx`: Live threat-vector chart derived from the same WebSocket alert buffer as the table.
- `frontend/src/components/SystemHealthPanel.tsx`: Throughput, latency, and zero-egress status display.
- `frontend/src/types/threat.ts`: TypeScript mirror of the backend alert contract.

## Runtime Architecture

1. Ingest flow metadata from the synthetic generator or Kafka/Zeek.
2. Record flow data into the Redis/in-memory sliding windows.
3. Run all six detection engines concurrently.
4. Normalize confidence to `0.00` through `1.00` and emit `ThreatAlertSchema` alerts.
5. Store alerts in ClickHouse and the memory ring.
6. Broadcast alerts through `ws://localhost:8000/ws/threats`.
7. Display live alerts in the frontend at `http://localhost:5173`.

The six threat classes are:

- `Volumetric & Protocol DDoS`
- `Botnet C2 Beaconing`
- `DGA & DNS Tunneling`
- `Encrypted Malware`
- `Reconnaissance Scan`
- `Data Exfiltration`

## Alert Contract

The canonical contract is defined in `backend/app/schemas.py` and mirrored in `frontend/src/types/threat.ts`.

Top-level alert fields include:

- UTC timestamp
- `flow_id`
- explicit source/destination IP and port fields
- protocol
- threat class
- confidence score
- ingest and processing latency
- structured evidence

Evidence includes generic flow metrics plus detector-specific values such as JA3/JA4, SNI, SPLT sequences, FFT concentration, beacon period, IAT standard deviation, DNS query metadata, n-gram score, PPS, Z-score, recon cardinalities, and total uploaded bytes.

## Important Time Handling

All threat timestamps are UTC.

ClickHouse can return `DateTime64` values as naive Python `datetime` objects. `backend/app/storage.py` must normalize naive database timestamps with `tzinfo=timezone.utc` before they are used by APIs or analytics. Do not call `.timestamp()` on a naive database value without normalizing it first; on a non-UTC host this shifts alerts outside the trend window.

The archive trend endpoint is:

`GET /api/analytics/trends?window_minutes=60&bucket_minutes=5`

It returns UTC-aligned buckets and includes the active current bucket.

## Dashboard Trend Behavior

The displayed Threat Vectors & Trends chart intentionally uses the live `alerts` array from `useThreatSocket`, not the historical archive endpoint. This keeps the graph synchronized with the Live Stream table:

- no historical spikes appear before current ingestion
- a vector increments only when a matching live alert arrives
- the rolling time window advances every three seconds
- the six vectors are drawn as separate lines

The REST trend endpoint remains useful for archive analytics and API consumers, but it is not the source for the live dashboard chart.

## API Endpoints

- `GET /api/health`: service state, pipeline state, passive zero-egress/read-only status, and latency telemetry.
- `GET /api/alerts`: archived alerts with pagination and optional threat-class filtering.
- `GET /api/metrics/throughput`: flows/sec, packets/sec, bytes/sec, Mbps, alert count, WebSocket clients, and latency.
- `GET /api/analytics/trends`: UTC-bucketed historical alert counts by threat class.
- `WS /ws/threats`: live alert stream; accepts `ping` and responds with `pong`.
- `GET /docs`: FastAPI OpenAPI documentation.

Additional functional endpoints:

- `PATCH /api/alerts/{flow_id}/status`: post-creation lifecycle status update.
- `GET /api/alerts?status=...`: lifecycle status filtering.
- `POST/GET /api/alerts/{flow_id}/notes`: separate analyst commentary storage.
- `GET /api/incidents`: source-IP correlated incident groups.
- `GET`/`PUT /api/config/thresholds` and `POST /api/config/thresholds/reset`: analyst-tunable
  detector thresholds with live values, valid ranges, and the engine consuming each parameter.
- `GET /api/export/iocs?window_minutes=X&format=json|csv`: opt-in IOC export.
- `GET`/`POST /api/config/suppressions` and `DELETE /api/config/suppressions/{id}`: suppression
  rule CRUD. Matching detections are still evaluated and persisted; only analyst delivery is withheld.
- `POST /api/replay/start` and `GET /api/replay/status`: isolated PCAP replay control.

Alert lifecycle values are `new`, `acknowledged`, `investigating`, `resolved`, and
`false_positive`. Alerts also carry optional `incident_id`, `suppressed`, `suppression_rule_id`,
and `source` (`live` or `replay`) fields; these are mirrored in the frontend TypeScript
contract.

Runtime configuration is held by `engine.runtime_config.RuntimeConfigStore`. Thresholds are read
live from `engine.config.THRESHOLDS` on every evaluation, so a change applies to the next
detection without restarting any process. Overrides and suppression rules are persisted to Redis
when it is reachable; `GET /api/config/thresholds` reports `persistent: false` and
`storage_mode: "memory"` when they are runtime-only and will be lost on restart.

Replay isolation uses a separate in-memory `DetectionPipeline` and temporary Zeek
log directory. Replayed alerts are archived with `source="replay"` and are not
broadcast to live WebSocket clients. A future implementation can move replay data
to a separate archive table if operational volume requires it.

Detector thresholds live in `engine/config.py` and are populated from named
environment variables. Detection algorithms are unchanged; `/api/config/thresholds`
exposes the effective read-only values.

Suppressed alerts remain auditable in storage with `suppressed=true`, but are not
broadcast by either the FastAPI background worker or Kafka consumer.

## Local Development

### Infrastructure

From the repository root:

```powershell
docker compose up -d
```

Services:

- Redpanda: `localhost:9092`
- Redpanda Console: `http://localhost:8080`
- Redis: `localhost:6379`
- ClickHouse HTTP: `http://localhost:8123/ping`
- Zeek watches `pcaps/` and writes to `logs/`

### Backend

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload --port 8000
```

The default mode is synthetic ingestion. The backend lifespan reads these important environment variables:

- `INGEST_SOURCE=synthetic|kafka`
- `ENABLE_BACKGROUND_GENERATOR=true|false`
- `SIMULATION_THREAT_RATIO`
- `SIMULATION_FLOWS_PER_SECOND`
- `KAFKA_BOOTSTRAP_SERVERS`
- `CLICKHOUSE_HOST`, `CLICKHOUSE_PORT`, `CLICKHOUSE_DB`
- `CORS_ORIGINS`

### Frontend

```powershell
Push-Location frontend
npm install
npm run dev
Pop-Location
```

The Vite proxy forwards `/api` to `http://localhost:8000` and `/ws` to `ws://localhost:8000`.

Production validation:

```powershell
Push-Location frontend
npm.cmd run build
Pop-Location
```

`npm.cmd` avoids PowerShell execution-policy problems with `npm.ps1` on Windows.

## Testing

Run the backend suite from the repository root:

```powershell
python -m unittest discover -s backend/tests -p "test_*.py"
```

The suite covers API/WebSocket behavior, all six detectors, feature windows, synthetic events, Zeek normalization, Kafka handoff, PCAP replay, and recent trend buckets. The current suite contains 51 tests.

## Storage Notes

ClickHouse is the preferred archive. If it is unavailable, `ClickHouseAlertStore` keeps a bounded in-memory ring buffer. The evidence JSON is persisted as a compatibility mechanism so newly added evidence fields can be reconstructed without requiring immediate ClickHouse table migrations.

Redis is the preferred feature store. If unavailable, `SlidingWindowStore` falls back to in-memory structures.

## Change Guidelines

- Preserve the Pydantic and TypeScript contract together.
- Keep all alert timestamps timezone-aware UTC.
- Preserve structured evidence fields; do not make the frontend parse detector metrics from `details` text.
- Keep live dashboard views based on the live WebSocket buffer when they are expected to match the live table.
- Use the existing six detector and sliding-window abstractions before adding new detection paths.
- Do not introduce outbound network actions into the passive ingest path.
- Run backend tests and `frontend` production build after cross-layer changes.

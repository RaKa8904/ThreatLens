# ThreatLens: Real-Time Passive Network Threat Detection & Live Forensic Intelligence

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4-06B6D4.svg?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![shadcn/ui](https://img.shields.io/badge/shadcn%2Fui-Components-000000.svg)](https://ui.shadcn.com/)
[![Redis](https://img.shields.io/badge/Redis-7.0%2B-DC382D.svg?logo=redis&logoColor=white)](https://redis.io/)
[![ClickHouse](https://img.shields.io/badge/ClickHouse-OLAP-FFCC01.svg?logo=clickhouse&logoColor=black)](https://clickhouse.com/)
[![Redpanda / Kafka](https://img.shields.io/badge/Redpanda-Kafka_API-FA2546.svg?logo=redpanda&logoColor=white)](https://redpanda.com/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)

ThreatLens is a read-only passive network threat detection and forensic intelligence prototype. Designed for packet-metadata inspection, sliding-window anomaly detection, and Security Operations Center (SOC) visualization, ThreatLens provides visibility into hostile network flows without decrypting payloads or causing inline backpressure.

---

## 1. System Architecture Overview

ThreatLens implements a decoupled, event-driven streaming architecture across six functional pipeline layers:

```mermaid
flowchart TD
    subgraph IngestLayer ["1. Ingestion Layer"]
        TAP["Passive Hardware TAP / SPAN Mirror"]
        Diode["Data-Diode Driver (TX Disabled, planned deployment hardening)"]
        TAP --> Diode
        MockProducer["Synthetic Flow Stream Generator (demo mode)"] -.-> Redpanda
    end

    subgraph ExtractionLayer ["2. Extraction Layer"]
        Diode --> Zeek["Zeek IDS Protocol Extractor"]
        Zeek -->|"network-flows (JSON)"| Redpanda["Redpanda Streaming Broker (Port 9092)"]
    end

    subgraph FeatureLayer ["3. Stateful Temporal Feature Store"]
        Redpanda --> StreamWorker["Feature Extraction Consumer"]
        StreamWorker <--> Redis10["Tier 1: 10s Window\n(Volumetric PPS & Fan-Out)"]
        StreamWorker <--> Redis60["Tier 2: 60s Window\n(DNS Entropy & Port Sweeps)"]
        StreamWorker <--> Redis300["Tier 3: 300s Window\n(C2 Heartbeats & Exfiltration)"]
    end

    subgraph DetectionLayer ["4. Multi-Threat Detection Pipeline"]
        Redis10 --> E1["Engine 1: Volumetric DDoS (Static-Baseline 3-Sigma)"]
        Redis10 --> E5["Engine 5: Reconnaissance Scan (Fan-Out Cardinality)"]
        Redis60 --> E3["Engine 3: DGA & DNS Tunneling (Shannon Entropy)"]
        Redis60 --> E5
        Redis300 --> E2["Engine 2: Botnet C2 Beaconing (IAT Variance & Jitter-Ratio Periodicity)"]
        Redis300 --> E4["Engine 4: Encrypted Malware (JA3 Threat-Intel Matching)"]
        Redis300 --> E6["Engine 6: Data Exfiltration (Byte Ratio Asymmetry)"]
    end

    subgraph DeliveryLayer ["5. Analytical Persistence & Delivery Hub"]
        E1 & E2 & E3 & E4 & E5 & E6 --> Aggregator["Unified Alert Aggregator & Scorer"]
        Aggregator -->|"threat-alerts"| AlertBus["Redpanda Alert Topic"]
        AlertBus --> CHClient["ClickHouse Ingest Client"]
        AlertBus --> WSHub["FastAPI WebSocket Gateway (Port 8000)"]
        CHClient --> ClickHouse[("ClickHouse OLAP Storage (Port 8123 / 9000)")]
    end

    subgraph PresentationLayer ["6. High-Density SOC Dashboard"]
        WSHub -->|"Live WebSocket Feed"| SOC["React 18 + shadcn/ui SOC Console (Port 5173)"]
        ClickHouse -.->|"Historical REST Queries"| FastAPIRest["FastAPI REST API"]
        FastAPIRest -.-> SOC
    end
```

---

## 2. Core Architectural Pillars

### A. Zero-Transmit Passive Ingestion
To eliminate the risk of operational disruption, transmission leakage, or discovery by adversaries, the sensor platform targets data-diode ingestion. The kernel-level hardening below is deployment-time configuration on the sensor host (planned; not enforced by this repository's code):
- Monitor interfaces run in unaddressed promiscuous mode with all Layer 2 and Layer 3 outbound transmissions disabled (`ip link set <dev> arp off; sysctl -w net.ipv6.conf.<dev>.disable_ipv6=1`).
- ARP, ICMP, DHCP, and IPv6 router solicitations are blocked at the kernel and physical driver levels.
- Non-intrusive protocol parsing: raw packet payloads are purged from memory immediately following header extraction and TLS handshake recording.

### B. Stateful Temporal Memory
Adversaries intentionally bypass static signature firewalls by staging attacks across multi-minute windows. ThreatLens deploys three synchronized sliding windows implemented using Redis sorted sets (`ZADD`, `ZRANGEBYSCORE`, `ZREMRANGEBYSCORE`) with bounded in-memory fallbacks:
- **10-Second Window**: Evaluates high-frequency volumetric spikes, SYN flood concentrations, and immediate destination endpoint fan-out sweeps.
- **60-Second Window**: Tracks domain lexical distributions, DNS resolution bursts, and horizontal port scanning spreads.
- **300-Second Window**: Captures persistent C2 beaconing heartbeats, inter-arrival time distributions, and sustained outbound data exfiltration ratios.
- **Automated Memory Bounds**: Timestamps older than the active horizon are evicted during every write cycle with an automatic TTL safeguard, preventing memory exhaustion.

### C. Non-Decrypted Cryptographic Profiling
ThreatLens enforces zero packet payload decryption, preserving network privacy and cryptographic integrity:
- **Cryptographic Fingerprinting (implemented)**: Extracts client JA3 hashes derived from TLS ClientHello parameters (ciphers, extensions, supported groups, and point formats) via Zeek's built-in JA3 policy.
- **JA4 Fingerprinting (planned)**: Requires the `foxio/ja4` Zeek package; not yet loaded by the bundled `local.zeek`.
- **Sequence of Packet Lengths and Times (SPLT, planned)**: Directional byte lengths and millisecond-precision packet intervals during connection negotiation to classify malicious tools without inspecting payload bytes.

---

## 3. Standardized Alert Contract

All detection modules, stream topics, database tables, and WebSocket payloads adhere to a synchronized contract enforced by Pydantic v2 (`backend/app/schemas.py`) and TypeScript interfaces (`frontend/src/types/threat.ts`):

```json
{
  "timestamp": "2026-09-13T01:00:00.000Z",
  "flow_id": "192.168.1.105:54321->198.51.100.44:8443",
  "threat_class": "Botnet C2 Beaconing",
  "confidence_score": 0.94,
  "evidence": {
    "inter_arrival_variance": 0.0012,
    "shannon_entropy": 3.82,
    "byte_ratio": 0.08,
    "fan_out_count": 1,
    "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
    "details": "Periodic beaconing detected at 15.0s intervals via jitter-ratio periodicity analysis."
  }
}
```

### Contract Properties

| Property | Type | Specification |
| :--- | :--- | :--- |
| `timestamp` | `datetime` (ISO 8601 UTC) | Exact UTC timestamp of threat evaluation. |
| `flow_id` | `string` | Canonical flow identifier in format: `src_ip:src_port->dst_ip:dst_port`. |
| `threat_class` | `ThreatClassEnum` | Standardized categorization across the 6 supported threat vectors. |
| `confidence_score` | `float` ($0.00 \le c \le 1.00$) | Probability and heuristic confidence index. |
| `evidence.inter_arrival_variance` | `float` | Population variance of packet inter-arrival times ($\Delta t$) in seconds squared. |
| `evidence.shannon_entropy` | `float` | Character-level Shannon entropy in bits ($0.0 \le H \le 8.0$). |
| `evidence.byte_ratio` | `float` | Outbound egress bytes divided by inbound ingress bytes. |
| `evidence.fan_out_count` | `integer` | Count of unique external IP addresses or ports contacted in the window. |
| `evidence.ja3_hash` | `string` (Nullable) | 32-character MD5 cryptographic hash of TLS ClientHello parameters. |
| `evidence.details` | `string` | Human-readable forensic summary and heuristic rationale. |

---

## 4. Detection Engines Matrix

| Threat Class | Detection Methodology | Mathematical Formulation | Window Tier | Operational Trigger |
| :--- | :--- | :--- | :--- | :--- |
| **Volumetric & Protocol DDoS** | Static-Baseline 3-Sigma Surge & SYN/UDP Ratio | $Z = \frac{\text{PPS} - \mu}{\sigma} > 3.0$ | 10 Seconds | $Z \ge 3.0$ with $\text{PPS} \ge 100$; SYN flood: SYN packet flow with $\ge 300$ packets, or $\text{SYN Ratio} \ge 0.85$ with $\text{PPS} \ge 100$; UDP storm: $\text{PPS} \ge 200$ with $Z \ge 3.0$. |
| **Botnet C2 Beaconing** | IAT Variance & Jitter-Ratio Periodicity | $\text{Var}(\Delta t) = \frac{1}{N} \sum (\Delta t - \mu)^2$ | 300 Seconds | Recurring connections ($\ge 3$ heartbeats) with mean period $\ge 1.0\text{ s}$ and $\text{Var}(\Delta t) \le 0.05\text{ s}^2$ or periodicity concentration $\ge 0.85$. |
| **DGA & DNS Tunneling** | Character Shannon Entropy & FQDN Length Analysis | $H(X) = -\sum P(x) \log_2 P(x)$ | 60 Seconds | Domain query $H(X) \ge 3.80\text{ bits}$, query length $> 60\text{ chars}$, or TXT/NULL query with payload $\ge 45\text{ chars}$ or $H(X) \ge 3.60\text{ bits}$. |
| **Encrypted Malware** | Threat-Intelligence JA3 Exact Matching | $\text{JA3} \in \text{SignatureDB}$ | 300 Seconds | Exact match against curated JA3 database (TrickBot, Cobalt Strike, Emotet, Metasploit, AsyncRAT, QakBot). |
| **Reconnaissance Scan** | Endpoint Cardinality Dispersion & SYN Asymmetry | $C = \vert \mathcal{D} \vert = \text{Card}(\text{Targets})$ | 10s / 60s | Single source IP probing $\ge 3$ distinct ports or IP addresses with probe profile ($\le 2$ packets, $\le 100\text{ bytes}$ per target). |
| **Data Exfiltration** | Outbound Flow Ratio & Volume Thresholds | $R = \frac{\text{Bytes(Egress)}}{\max(\text{Bytes(Ingress)}, 1)}$ | 300 Seconds | $\ge 1\text{ MB}$ outbound with $R \ge 20.0$, or $\ge 5\text{ MB}$ outbound with $R \ge 10.0$. |

---

## 5. Repository Structure

```
ThreatLens/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI application, REST endpoints, WebSocket hub, Kafka wiring & synthetic demo producer
│   │   ├── schemas.py              # Pydantic v2 schemas: FlowEventSchema, ThreatClassEnum, EvidenceSchema, ThreatAlertSchema
│   │   ├── storage.py              # ClickHouseAlertStore: table initialization, batch insert & memory ring buffer
│   │   └── websocket_manager.py    # ConnectionManager: live client connection tracking & alert broadcast
│   ├── requirements.txt            # Backend dependencies (FastAPI, Redis, ClickHouse, Pydantic, Kafka, Scikit-learn, httpx)
│   └── tests/
│       ├── __init__.py
│       ├── test_api.py             # FastAPI REST & WebSocket endpoint integration tests (TestClient)
│       ├── test_alert_consumer.py  # KafkaAlertConsumer: valid/malformed alert processing, persistence, broadcast
│       ├── test_engines.py         # Multi-model detection engines and pipeline integration tests
│       ├── test_features.py        # Statistical metrics, Shannon entropy, and SlidingWindowStore tests
│       ├── test_flow_event_schema.py # FlowEventSchema contract: producer conformance, invalid rejection, WS config
│       ├── test_ingest_contracts.py  # Canonical topics, no stale split topics, Kafka dependency, no pipeline bypass
│       ├── test_no_label_leak.py   # Meta-test: no detector reads simulated_label
│       ├── test_pcap_replay.py     # Zeek log normalization, shipper publication, PCAP replay detection, alert persistence
│       └── test_stream_worker.py   # Message parsing, canonical dispatch, worker delegation, alert publishing
├── engine/
│   ├── __init__.py
│   ├── features/
│   │   ├── __init__.py
│   │   ├── metrics.py              # Shannon entropy, flow ratio, IAT variance, and fan-out calculators
│   │   └── store.py                # SlidingWindowStore: Redis sorted sets (10s, 60s, 300s) with in-memory deque fallback
│   ├── models/
│   │   ├── __init__.py
│   │   ├── aggregator.py           # AlertAggregator: concurrent multi-model dispatch & confidence score normalizer
│   │   ├── base.py                 # BaseDetectionEngine interface & DetectionCandidate dataclass
│   │   ├── beaconing_engine.py     # Botnet C2 beaconing engine (IAT variance & jitter-ratio periodicity)
│   │   ├── ddos_engine.py          # Volumetric DDoS engine (static-baseline 3-sigma PPS & SYN flood evaluation)
│   │   ├── dns_engine.py           # DGA & DNS tunneling engine (Character Shannon entropy & payload size thresholds)
│   │   ├── exfiltration_engine.py  # Data exfiltration engine (Outbound-to-inbound byte asymmetry & volume thresholds)
│   │   ├── malware_engine.py       # Encrypted malware engine (JA3 threat-intelligence signature matching)
│   │   └── recon_engine.py         # Reconnaissance scan engine (Multi-tier endpoint cardinality dispersion)
│   ├── kafka_consumer.py           # KafkaAlertConsumer: threat-alerts topic → persistence + WebSocket broadcast
│   ├── pipeline.py                 # DetectionPipeline orchestrator & canonical event→store dispatch
│   └── stream_worker.py            # StreamWorker: network-flows topic → pipeline → threat-alerts topic
├── frontend/
│   ├── index.html                  # HTML5 template with dark theme and Inter/JetBrains Mono fonts
│   ├── package.json                # React 18, Vite, Tailwind CSS, Recharts, Hugeicons, and class utilities
│   ├── postcss.config.js           # PostCSS Tailwind CSS pipeline
│   ├── tailwind.config.js          # Tailwind CSS theme tokens & dark color configurations
│   ├── tsconfig.json               # TypeScript compiler options & '@/*' path alias
│   ├── tsconfig.node.json          # Vite node configuration
│   ├── vite.config.ts              # Vite dev server with proxy routing for /api and /ws
│   └── src/
│       ├── App.tsx                 # Main SOC Enclave application layout with KPI cards & live data feeds
│       ├── index.css               # Global styles, dark tokens, and customized SOC scrollbars
│       ├── main.tsx                # React DOM root entrypoint
│       ├── components/
│       │   ├── ForensicDrawer.tsx  # Slide-over forensic sheet: telemetry metrics, JA3 copy & raw JSON viewer
│       │   ├── Navbar.tsx          # Brand header: live stream pulse pill, real-time UTC clock & freeze toggle
│       │   ├── ThreatTable.tsx     # High-density alert table: severity badges, progress bars, search & filters
│       │   ├── ThroughputGauge.tsx # Recharts Area chart: real-time flows/sec, packets/sec (PPS) & peak Mbps
│       │   └── ui/                 # Reusable shadcn/ui primitives (badge, button, card, sheet, table, tabs, tooltip)
│       ├── hooks/
│       │   └── useThreatSocket.ts  # Resilient auto-reconnecting WebSocket hook with rolling buffer & pause toggle
│       ├── lib/
│       │   └── utils.ts            # Class merging utility (clsx + tailwind-merge) and formatting helpers
│       └── types/
│           └── threat.ts           # Synchronized TypeScript interfaces matching backend Pydantic schemas
├── ingest/
│   ├── __init__.py
│   ├── producers/
│   │   ├── __init__.py
│   │   ├── mock_producer.py        # Synthetic multi-class network flow stream generator and Kafka publisher
│   │   └── zeek_kafka_shipper.py   # Zeek JSON log tailer/normalizer publishing to network-flows
│   └── zeek/                       # Zeek sensor container (Dockerfile, local.zeek policy, PCAP replay scripts)
├── docker-compose.yml              # Multi-service hybrid pipeline (Redpanda, Redpanda Console, Redis, ClickHouse)
├── .env.example                    # Service ports, hostnames, topics, ingest source, and detection parameters
└── .gitignore                      # Environment secrets, logs, PCAPs, and build artifact exclusions
```

---

## 6. Local Quickstart Guide

### System Prerequisites
- **Python**: Version 3.11 or higher
- **Node.js**: Version 18 or higher (with `npm`)
- **Docker**: Docker Engine and Docker Compose v2+

---

### Step 1: Clone Repository & Configure Environment
```bash
git clone https://github.com/RaKa8904/ThreatLens.git
cd ThreatLens
cp .env.example .env
```

---

### Step 2: Bootstrap Infrastructure Services (Docker)
Start the message broker, in-memory sliding-window store, and analytical OLAP archive:
```bash
docker compose up -d
```

Service access points:
- **Redpanda Broker**: `localhost:9092`
- **Redpanda Web Console**: [http://localhost:8080](http://localhost:8080)
- **Redis Feature Store**: `localhost:6379`
- **ClickHouse HTTP Interface**: [http://localhost:8123/ping](http://localhost:8123/ping)

---

### Step 3: Set Up Backend & Launch FastAPI Gateway
Initialize the Python virtual environment, install dependencies, and launch the Uvicorn server:
```bash
# Initialize virtual environment
python -m venv .venv

# Activate environment:
# On Linux / macOS:
source .venv/bin/activate
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Install backend dependencies
pip install -r backend/requirements.txt

# Launch FastAPI server (Kafka required: starts StreamWorker, alert consumer,
# and — with INGEST_SOURCE=synthetic — the demo event producer)
uvicorn backend.app.main:app --reload --port 8000
```

> **Note**: The backend requires a running Kafka/Redpanda broker (Step 2). If Kafka is unreachable, the API still serves REST/WebSocket endpoints, but live detection is disabled and the failure is logged as an ERROR and surfaced under `services.kafka` in `/api/health`. Set `ENABLE_BACKGROUND_GENERATOR=false` to run the API without background workers.

FastAPI endpoints:
- **Interactive OpenAPI Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Healthcheck Endpoint**: [http://localhost:8000/api/health](http://localhost:8000/api/health)
- **Historical Alerts Endpoint**: [http://localhost:8000/api/alerts](http://localhost:8000/api/alerts)
- **WebSocket Broadcast Stream**: `ws://localhost:8000/ws/threats`

---

### Step 4: Set Up Frontend & Launch SOC Enclave Dashboard
Open a secondary terminal to launch the React 18 dashboard:
```bash
cd frontend
npm install
npm run dev
```

Open the dashboard in your browser: [http://localhost:5173](http://localhost:5173)

---

### Step 5: Execute Complete Test Suite
Run all 110 contract, statistical, detection engine, pipeline, ingest, and API integration tests:
```bash
python -m unittest discover -s backend/tests -t . -v
```

The suite is hermetic: Kafka and other background workers are disabled during tests, and no external services are required.

---

## 7. Roadmap & Milestone Status

| Milestone | Phase | Scope & Deliverables | Status |
| :---: | :--- | :--- | :---: |
| **01** | Core Contracts & Docker Stack | Pydantic v2 schemas, synchronized TypeScript types, and multi-service `docker-compose.yml`. | Complete |
| **02** | Feature Store & Synthetic Stream | SlidingWindowStore (10s, 60s, 300s), Shannon entropy, IAT variance, and synthetic generator. | Complete |
| **03** | Multi-Threat Detection Pipeline | 6 specialized detection engines (heuristic/statistical) and AlertAggregator. | Complete |
| **04** | Streaming Gateway & Persistence | ClickHouse columnar storage client, FastAPI REST API, and WebSocket broadcast hub. | Complete |
| **05** | High-Density SOC Dashboard | React 18 dashboard with shadcn/ui, Hugeicons, Recharts, slide-over ForensicDrawer, and freeze toggle. | Complete |
| **06** | Hardware TAP & Live PCAP Replay | Containerized Zeek sensor scripts, Zeek→Kafka shipper, and PCAP replay ingestion. Optical TAP interface bindings and live sensor deployment pending. | Partial |

---

## 8. Implemented vs Planned

### Implemented
- Unified Kafka ingest: Zeek shipper and synthetic demo producer both publish JSON `FlowEvent` records to `network-flows`; a single StreamWorker feeds the canonical DetectionPipeline; alerts are published to `threat-alerts` and consumed by the backend for ClickHouse persistence and WebSocket broadcast.
- FlowEventSchema contract (Pydantic v2) enforced at pipeline entry; malformed messages counted and skipped.
- Six statistical/heuristic detection engines over Redis-backed sliding windows (10s/60s/300s) with in-memory fallback.
- JA3 fingerprint extraction via Zeek's stock JA3 policy and exact-match threat-intel detection.
- Zeek sensor container with PCAP replay (`zeek -r`) and JSON log shipping; synthetic PCAP generator for offline testing.
- ClickHouse alert archive with in-memory ring-buffer fallback; REST API (`/api/health`, `/api/alerts`, `/api/metrics/throughput`) and `/ws/threats` WebSocket feed.
- 110-test hermetic suite (contracts, engines, features, ingest, replay, API).

### Planned
- Kernel-level zero-transmit hardening (data diode, ARP/ICMP/DHCP/IPv6 suppression) on the sensor host at deployment time.
- JA4 fingerprinting (requires the `foxio/ja4` Zeek package).
- SPLT (sequence of packet lengths and times) feature extraction.
- Calibrated baselines for the DDoS engine (currently a configurable static baseline) and z-score-based exfiltration scoring.
- Real-dataset evaluation (e.g., CTU-13) and measured detection-latency benchmarks.

---

## License

TBD — license decision pending.

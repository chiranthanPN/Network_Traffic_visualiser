# Network Traffic Analyser

A real-time network security visualization dashboard that captures live network packets, groups them into flows, and classifies each flow using two complementary AI models — a **Graph Attention Network (GAT)** for graph-level anomaly detection and an **Isolation Forest** for flow-level outlier detection. Results are fused into a single risk level (**LOW**, **MEDIUM**, or **HIGH**) and streamed over WebSocket to an interactive React dashboard.

---

## Architecture

```
┌─────────────────────────┐       WebSocket        ┌──────────────────────────┐
│    React Frontend       │ ◄──────────────────── │    FastAPI Backend        │
│    (Vite + TypeScript   │    /api/ws              │                          │
│     + Tailwind CSS)     │                         │   ┌──────────────────┐   │
│                         │    REST                 │   │   Scapy Sniffer  │   │
│  ┌─ Live Network Graph  │ ◄── /api/health         │   │   5-sec windows  │   │
│  ├─ Alerts Feed         │ ◄── /api/monitor/start  │   └────────┬─────────┘   │
│  ├─ Flow Table          │ ◄── /api/monitor/stop   │            │             │
│  ├─ Traffic Chart       │ ◄── /api/monitor/demo   │   ┌────────▼─────────┐   │
│  └─ Node / Edge Detail  │                         │   │  FlowProcessor   │   │
└─────────────────────────┘                         │   └────────┬─────────┘   │
                                                    │            │             │
                                                    │   ┌────────▼─────────┐   │
                                                    │   │ DetectionEngine  │   │
                                                    │   │  ├ Isolation     │   │
                                                    │   │  │   Forest      │   │
                                                    │   │  └ GAT Model     │   │
                                                    │   └────────┬─────────┘   │
                                                    │            │             │
                                                    │   ┌────────▼─────────┐   │
                                                    │   │  WS Broadcast    │   │
                                                    │   └──────────────────┘   │
                                                    └──────────────────────────┘
```

---

## ML Pipeline

The detection pipeline runs entirely on the backend and is **not** modified by the frontend.

### 1 — Packet Capture

Scapy captures IP packets on all interfaces and groups them into bidirectional flows keyed by `(src_ip, dst_ip, src_port, dst_port, protocol)`.

### 2 — Feature Extraction

Each 5-second analysis window produces per-flow features:

| Feature | Description |
|---------|-------------|
| `packet_count` | Total packets in the flow |
| `byte_count` | Total bytes |
| `duration` | Flow lifetime (seconds) |
| `packets_per_second` | Packet rate |
| `bytes_per_second` | Byte rate |
| `average_packet_size` | Mean packet length |
| `unique_destination_ips` | Distinct destination IPs |
| `unique_destination_ports` | Distinct destination ports |
| `tcp_syn_count` | TCP SYN flags observed |
| `tcp_rst_count` | TCP RST flags observed |

### 3 — Isolation Forest (flow-level)

A scikit-learn `IsolationForest` (200 estimators, `contamination="auto"`) trained on normal traffic (`data/normal_traffic.csv`). Returns a binary `is_anomaly` flag and a `decision_score` (higher = more normal; **not** a probability).

### 4 — GAT (graph-level)

A Graph Attention Network built with PyTorch Geometric. A live graph is constructed where:

- **Nodes** = unique IP addresses (14 features: flow_count, outbound/inbound flows, outbound/inbound packets, outbound/inbound bytes, average_duration, average_bytes_per_second, average_packets_per_second, average_packet_size, tcp_flows, udp_flows, unique_peers)
- **Directed edges** = source IP → destination IP

The model outputs an `attack_score` compared against a learned `threshold` (from `gat_threshold.json`). The score is **not** a calibrated probability.

### 5 — Fusion

The `DetectionEngine` fuses both model decisions per flow:

| Isolation Forest | GAT | → Risk Level |
|:---:|:---:|:---:|
| Normal | Normal | **LOW** |
| Anomaly | Normal | **MEDIUM** |
| Normal | Anomaly | **MEDIUM** |
| Anomaly | Anomaly | **HIGH** |

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.9+ | `py` or `python` |
| Node.js | 18+ | For the frontend |
| npm | 9+ | |
| Npcap | 1.89+ | Required on Windows for raw packet capture (installer bundled as `npcap-1.89.exe`) |

> **Windows:** Run the backend terminal **as Administrator** for Scapy to capture packets.

---

## Setup & Run

### Quick Start (Single-Command Launcher)

To run the entire project in proper sequence without managing separate terminal windows:

```powershell
# Run the root launcher (starts backend first, verifies health, then starts frontend)
python run.py
```

Or on Windows:
```cmd
run.bat
```

> **What the launcher does automatically:**
> 1. Verifies Python and Node.js/npm environments.
> 2. Auto-installs frontend dependencies (`npm install`) if `node_modules` is missing.
> 3. Starts the FastAPI backend on `http://localhost:8000`.
> 4. Polls `/api/health` until the ML models (GAT + Isolation Forest) and API report healthy.
> 5. Starts the Vite frontend on `http://localhost:5173`.
> 6. Shuts both servers down cleanly on `Ctrl+C`.

---

### Alternative: Manual Start (Separate Terminals)

If you prefer running services independently:

#### 1 — Backend

```powershell
cd backend

# Install Python dependencies (first time)
pip install -r requirements.txt

# Start the API server (as Administrator for live capture)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify:

```
GET http://localhost:8000/api/health
→ {"api": true, "capture": false, "isolation_forest": true, "gat": true}
```

Both models should report `true`. If Isolation Forest reports `false`, retrain it:

```powershell
cd backend
python -m app.models.train_isolation_forest
```

#### 2 — Frontend

```powershell
cd frontend

# Install Node packages (first time)
npm install

# Start the dev server
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Using the Dashboard

1. Open `http://localhost:5173`
2. The **header** shows live status for API, Isolation Forest, GAT, and Capture
3. Click **Start Monitoring** — the backend begins a Scapy capture loop (requires admin privileges)
4. The **live network graph** populates automatically every 5 seconds
5. **Click any node** → IP stats, peer list, and recent communications in the sidebar
6. **Click any edge** → full flow details: IF decision score, GAT attack score, and fused risk level
7. **Click any alert** in the sidebar → jumps to that flow's detail panel
8. **Flow table** at the bottom: search by IP or protocol, filter by risk level
9. Click **Stop Monitoring** to halt capture

### Demo Replay Mode

Click **Replay Sample** to stream the labeled synthetic dataset (`backend/data/demo_anomaly_flows.csv`) through the same detection models. The dataset contains ~1000 flows across six scenarios:

| Scenario | Risk Profile | Description |
|----------|:---:|-------------|
| `ordinary_traffic` | Low | Normal browsing / DNS |
| `port_scan` | Medium | Single-packet probes across many ports |
| `login_burst` | Medium | Rapid SSH login attempts |
| `dns_burst` | Medium | High-volume DNS queries |
| `syn_flood` | High | Massive SYN packet flood |
| `traffic_flood` | High | Volumetric DDoS traffic |
| `large_exfiltration` | High | Large outbound data transfer |

> Demo mode does not require admin privileges or Npcap — flows are read from CSV and analysed by the models.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Model + capture status |
| `GET` | `/api/status` | Alias for `/api/health` |
| `POST` | `/api/monitor/start` | Start live packet capture |
| `POST` | `/api/monitor/demo` | Start demo replay from CSV |
| `POST` | `/api/monitor/stop` | Stop capture or demo |
| `GET` | `/api/monitor/status` | Is capture running? |
| `WS` | `/api/ws` | Live stream of `network_update` events |

### WebSocket Message Schema

```json
{
  "type": "network_update",
  "mode": "live",
  "timestamp": 1727318400.0,
  "window_duration": 5,
  "packets_captured": 120,
  "total_flows": 14,
  "anomalies": 2,
  "risk_counts": { "LOW": 12, "MEDIUM": 1, "HIGH": 1 },
  "flows": [
    {
      "source_ip": "192.168.1.10",
      "destination_ip": "8.8.8.8",
      "source_port": 50000,
      "destination_port": 53,
      "protocol": "UDP",
      "packet_count": 10,
      "byte_count": 1000,
      "isolation_forest": { "is_anomaly": false, "decision_score": 0.1234 },
      "gat":              { "is_anomaly": false, "attack_score": 0.2123, "threshold": 0.8 },
      "fusion":           { "isolation_forest_anomaly": false, "gat_anomaly": false, "risk_level": "LOW" }
    }
  ]
}
```

In demo mode, each flow also includes `"demo_scenario"` and `"expected_label"` fields.

---

## Model Files

| File | Description | Status |
|------|-------------|--------|
| `trained_models/gat/gat_model_leakage_safe.pt` | Leakage-safe GAT checkpoint | ✅ Present |
| `trained_models/gat/gat_threshold.json` | GAT anomaly threshold | ✅ Present |
| `data/gat/gat_graph_leakage_safe.pt` | GAT training graph | ✅ Present |
| `trained_models/isolation_forest.pkl` | Trained Isolation Forest model | ✅ Present |

### Training Data

| File | Description |
|------|-------------|
| `data/normal_traffic.csv` | Normal flow data used to train the Isolation Forest |
| `data/demo_anomaly_flows.csv` | Mixed-risk synthetic flows for demo replay (port scans, SYN floods, exfiltration, etc.) |
| `data/normal_traffic_backup.csv` | Backup of normal training data |
| `data/demo_anomaly_flows_backup.csv` | Backup of demo dataset |

To regenerate the synthetic datasets:

```powershell
cd backend
python process_data.py
```

To retrain the Isolation Forest:

```powershell
cd backend
python -m app.models.train_isolation_forest
```

---

## Project Structure

```
Network_Traffic_visualiser/
├── .gitignore
├── README.md
├── run.py                          ← Unified single-command launcher (backend + health check + frontend)
├── run.bat                         ← Windows one-click launcher
├── index.js                        ← Root placeholder
├── package.json                    ← Root package manifest
├── npcap-1.89.exe                  ← Npcap installer (Windows)
│
├── backend/
│   ├── requirements.txt
│   ├── process_data.py             ← Generate synthetic training & demo CSVs
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 ← FastAPI app + CORS
│   │   ├── api/
│   │   │   └── routes.py           ← REST + WebSocket endpoints, demo replay
│   │   ├── capture/
│   │   │   ├── packet_capture.py   ← Scapy packet handler + FlowProcessor
│   │   │   └── live_detection.py   ← CLI live detection (standalone)
│   │   ├── detection/
│   │   │   ├── detection_engine.py ← IF + GAT fusion engine
│   │   │   └── alert_manager.py
│   │   ├── features/
│   │   │   ├── feature_extractor.py ← Flow feature extraction
│   │   │   ├── data_collector.py
│   │   │   └── test_feature_extractor.py
│   │   ├── graph/
│   │   │   ├── __init__.py
│   │   │   ├── live_graph_builder.py   ← Build PyG graph from flows
│   │   │   └── build_leakage_safe_graph.py
│   │   └── models/
│   │       ├── gat_model.py           ← GATNetwork definition
│   │       ├── gat_inference.py       ← GATInference class
│   │       ├── isolation_forest.py    ← IF training, loading, prediction
│   │       ├── train_isolation_forest.py
│   │       ├── train_gat_leakage_safe.py
│   │       ├── test_gat_inference.py
│   │       ├── test_isolation_forest.py
│   │       ├── gat_threshold_analysis_leakage_safe.py
│   │       └── gat/
│   │           ├── __init__.py
│   │           ├── analyze_gat_dataset.py
│   │           ├── check_missing_values.py
│   │           └── inspect_webattacks.py
│   ├── data/
│   │   ├── normal_traffic.csv
│   │   ├── normal_traffic_backup.csv
│   │   ├── demo_anomaly_flows.csv
│   │   ├── demo_anomaly_flows_backup.csv
│   │   └── gat/
│   │       ├── gat_graph.pt
│   │       └── gat_graph_leakage_safe.pt
│   └── trained_models/
│       ├── isolation_forest.pkl
│       └── gat/
│           ├── .gitkeep
│           ├── gat_model_leakage_safe.pt
│           └── gat_threshold.json
│
└── frontend/
    ├── index.html
    ├── package.json
    ├── package-lock.json
    ├── tsconfig.json
    ├── tsconfig.node.json
    ├── vite.config.ts
    ├── tailwind.config.js
    ├── postcss.config.js
    └── src/
        ├── main.tsx                    ← React entry point
        ├── index.css                   ← Tailwind directives
        ├── App.tsx                     ← Main dashboard
        ├── components/
        │   └── TrafficChart.tsx        ← Recharts live chart (switchable metrics)
        ├── hooks/
        │   └── useNetworkWebSocket.ts  ← WebSocket with exponential backoff
        ├── services/
        │   └── api.ts                  ← REST API client
        └── types/
            └── network.ts              ← TypeScript interfaces
```

---

## Contributors

- [chiranthanPN](https://github.com/chiranthanPN)
- [vireshanand278](https://github.com/vireshanand278)
- [yogeshperumal41-droid](https://github.com/yogeshperumal41-droid)

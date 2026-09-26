# Network Traffic Analyser

A real-time network security visualization dashboard powered by a **Graph Attention Network (GAT)** and **Isolation Forest**, with a live interactive React frontend.

---

## Architecture

```
┌─────────────────────┐        WebSocket        ┌─────────────────────────┐
│   React Frontend    │ ←───────────────────── │   FastAPI Backend        │
│   (Vite + TS +      │   /api/ws               │                         │
│    TailwindCSS)     │                         │  ┌─────────────────┐   │
│                     │   REST                  │  │  Scapy Sniffer  │   │
│  Live Network Graph │ ←── /api/health         │  │  5-sec windows  │   │
│  Alerts Feed        │ ←── /api/monitor/start  │  └────────┬────────┘   │
│  Flow Table         │ ←── /api/monitor/stop   │           │            │
│  Traffic Chart      │                         │  ┌────────▼────────┐   │
│  Node/Edge Details  │                         │  │  FlowProcessor  │   │
└─────────────────────┘                         │  └────────┬────────┘   │
                                                │           │            │
                                                │  ┌────────▼────────┐   │
                                                │  │ DetectionEngine │   │
                                                │  │ ├ Isolation     │   │
                                                │  │ │   Forest      │   │
                                                │  │ └ GAT Model     │   │
                                                │  └────────┬────────┘   │
                                                │           │            │
                                                │  ┌────────▼────────┐   │
                                                │  │  WS Broadcast   │   │
                                                │  └─────────────────┘   │
                                                └─────────────────────────┘
```

---

## Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.9+ |
| Node.js | 18+ |
| npm | 9+ |

> **Windows users:** Packet capture with Scapy requires **Npcap** (free). Download from https://npcap.com/.  
> **Start backend as Administrator** to allow raw packet capture.

---

## Setup & Run

### 1 — Backend

```powershell
cd backend

# Install dependencies (first time only)
python -m pip install -r requirements.txt fastapi uvicorn

# Start the API server (run as Administrator for live capture)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify the backend is up:
```
http://localhost:8000/api/health
→ {"api":true,"capture":false,"isolation_forest":false,"gat":true}
```

> **Note:** `isolation_forest: false` means `trained_models/isolation_forest.pkl` is missing.  
> The system still works — GAT handles detection. Train Isolation Forest separately with `python -m app.models.train_isolation_forest`.

---

### 2 — Frontend

```powershell
cd frontend

# Install Node packages (first time only)
npm install

# Start the development server
npm run dev
```

Open http://localhost:5173 in your browser.

---

## Using the Dashboard

1. Open the frontend at `http://localhost:5173`
2. The **header** shows model/capture status (API · Isolation Forest · GAT · Capture)
3. Click **Start Monitoring** — the backend starts a Scapy capture loop
4. The **live network graph** populates automatically every 5 seconds
5. **Click any node** → see IP stats and peer communications in the sidebar
6. **Click any edge** → see full flow details with IF score, GAT score, and fused risk
7. **Click any alert** → jumps to that flow's detail panel
8. **Flow table** at the bottom: search by IP or protocol, filter by risk level
9. Click **Stop Monitoring** to halt capture cleanly

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Model + capture status |
| `GET` | `/api/status` | Alias for health |
| `POST` | `/api/monitor/start` | Start packet capture loop |
| `POST` | `/api/monitor/stop` | Stop capture |
| `GET` | `/api/monitor/status` | Is capture running? |
| `WS` | `/api/ws` | Live stream of `network_update` events |

### WebSocket Message Schema

```json
{
  "type": "network_update",
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

---

## Model Files

| File | Status |
|------|--------|
| `trained_models/gat/gat_model_leakage_safe.pt` | ✅ Present |
| `trained_models/gat/gat_threshold.json` | ✅ Present |
| `data/gat/gat_graph_leakage_safe.pt` | ✅ Present |
| `trained_models/isolation_forest.pkl` | ⚠️ Missing — train to enable |

---

## Project Structure

```
Network_Traffic_visualiser_Minor_project/
├── backend/
│   ├── app/
│   │   ├── api/routes.py          ← FastAPI endpoints + WebSocket
│   │   ├── capture/
│   │   │   ├── packet_capture.py  ← Scapy packet handler
│   │   │   └── live_detection.py  ← CLI live detection (standalone)
│   │   ├── detection/
│   │   │   ├── detection_engine.py ← IF + GAT fusion
│   │   │   └── alert_manager.py
│   │   ├── features/
│   │   │   ├── feature_extractor.py ← FlowProcessor
│   │   │   └── data_collector.py
│   │   ├── graph/
│   │   │   └── live_graph_builder.py ← PyG graph from flows
│   │   ├── models/
│   │   │   ├── gat_model.py       ← GATNetwork definition
│   │   │   ├── gat_inference.py   ← GATInference class
│   │   │   └── isolation_forest.py
│   │   └── main.py
│   ├── data/gat/
│   └── trained_models/gat/
│
└── frontend/
    ├── src/
    │   ├── App.tsx                ← Main dashboard
    │   ├── components/
    │   │   └── TrafficChart.tsx   ← Recharts live chart
    │   ├── hooks/
    │   │   └── useNetworkWebSocket.ts  ← WS with backoff
    │   ├── services/
    │   │   └── api.ts             ← REST client
    │   └── types/
    │       └── network.ts         ← TypeScript interfaces
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.js
    └── tsconfig.json
```

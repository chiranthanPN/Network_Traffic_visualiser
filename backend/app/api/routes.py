import asyncio
import csv
import time
import math
from pathlib import Path
from typing import List, Any, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request, Query

from app.capture.packet_capture import flow_processor, process_packet, packet_counter
import app.capture.packet_capture as pc
from app.detection.detection_engine import DetectionEngine
from scapy.all import sniff

router = APIRouter(prefix="/api")
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DEFAULT_DEMO_DATASET = "demo_anomaly_flows.csv"

DATASET_METADATA = {
    "demo_anomaly_flows.csv": {
        "name": "Mixed Threats (Port Scan, Flood, Exfiltration)",
        "description": "Multi-scenario attack traffic with port scans, SYN floods, login bursts, and exfiltration",
        "category": "threats"
    },
    "normal_traffic.csv": {
        "name": "Normal Baseline Traffic",
        "description": "Ordinary benign web browsing, HTTPS requests, and DNS lookups",
        "category": "normal"
    },
    "normal_traffic_demo.csv": {
        "name": "Clean Traffic Sample",
        "description": "Clean standard background UDP/TCP communications",
        "category": "normal"
    }
}

class MonitorState:
    def __init__(self):
        self.is_running = False
        self.task = None
        self.engine = None
        self.active_connections: List[WebSocket] = []
        self.window_size = 5
        self.mode = None
        self.active_dataset = None

state = MonitorState()
try:
    state.engine = DetectionEngine()
except Exception as e:
    print(f"Engine init error: {e}")

def make_json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(i) for i in obj]
    elif isinstance(obj, set):
        return [make_json_safe(i) for i in obj]
    elif isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return 0.0
        return obj
    elif hasattr(obj, 'item') and callable(getattr(obj, 'item')):
        return obj.item()
    return obj

def sniff_window(timeout):
    pc.packet_counter = 0
    sniff(prn=process_packet, store=False, timeout=timeout)
    return pc.packet_counter

async def broadcast(payload):
    payload = make_json_safe(payload)
    disconnected = []
    for ws in state.active_connections:
        try:
            await ws.send_json(payload)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        if ws in state.active_connections:
            state.active_connections.remove(ws)

async def capture_loop():
    if state.engine is None:
        try:
            state.engine = await asyncio.to_thread(DetectionEngine)
        except Exception as e:
            print(f"Error loading DetectionEngine: {e}")
    
    while state.is_running:
        try:
            captured = await asyncio.to_thread(sniff_window, state.window_size)
        except Exception as e:
            state.is_running = False
            error_msg = str(e)
            if "Permission" in error_msg or "Operation not permitted" in error_msg:
                error_msg = "Packet capture requires administrator/root privileges."
            
            error_payload = {"type": "error", "message": error_msg}
            await broadcast(error_payload)
            break
        
        if not state.is_running:
            break
            
        flows = flow_processor.get_features()
        flow_processor.clear_flows()
        
        captured_bytes = sum(int(f.get("byte_count", 0)) for f in flows) if flows else 0

        if flows:
            results = state.engine.analyze(flows)
        else:
            results = {"total_flows": 0, "anomalies": 0, "results": []}
            
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for r in results["results"]:
            risk = r.get("fusion", {}).get("risk_level", "LOW")
            if risk in counts:
                counts[risk] += 1
                
        payload = {
            "type": "network_update",
            "timestamp": time.time(),
            "window_duration": state.window_size,
            "packets_captured": captured,
            "bytes_captured": captured_bytes,
            "total_flows": results["total_flows"],
            "anomalies": results["anomalies"],
            "risk_counts": counts,
            "flows": results["results"]
        }
        
        payload["mode"] = "live"
        await broadcast(payload)

    state.mode = None
    state.active_dataset = None

async def demo_loop(dataset_name: str = DEFAULT_DEMO_DATASET):
    try:
        # Prevent path traversal and verify existence
        safe_name = Path(dataset_name).name
        csv_path = (DATA_DIR / safe_name).resolve()
        
        if not csv_path.exists() or not csv_path.is_relative_to(DATA_DIR):
            csv_path = DATA_DIR / DEFAULT_DEMO_DATASET

        with csv_path.open(newline="", encoding="utf-8", errors="ignore") as data_file:
            rows = list(csv.DictReader(data_file))

        if not rows:
            raise ValueError(f"The demo dataset '{safe_name}' is empty.")

        for offset in range(0, len(rows), 8):
            if not state.is_running or state.mode != "demo":
                break

            batch = rows[offset:offset + 8]
            flows = []
            for row in batch:
                flow = {
                    "source_ip": row.get("source_ip", "192.168.1.10"),
                    "destination_ip": row.get("destination_ip", "10.0.0.1"),
                    "protocol": row.get("protocol", "TCP"),
                    "scenario": row.get("scenario", "traffic_sample"),
                    "expected_label": row.get("expected_label", "NORMAL")
                }
                
                try:
                    flow["source_port"] = int(float(row.get("source_port", 80)))
                except (ValueError, TypeError):
                    flow["source_port"] = 80
                    
                try:
                    flow["destination_port"] = int(float(row.get("destination_port", 80)))
                except (ValueError, TypeError):
                    flow["destination_port"] = 80

                for key in (
                    "packet_count", "byte_count", "duration", "packets_per_second",
                    "bytes_per_second", "average_packet_size", "unique_destination_ips",
                    "unique_destination_ports", "tcp_syn_count", "tcp_rst_count"
                ):
                    raw_val = row.get(key, 0)
                    try:
                        val = float(raw_val) if raw_val not in (None, "") else 0.0
                    except (ValueError, TypeError):
                        val = 0.0
                        
                    flow[key] = val
                    if key in {
                        "packet_count", "byte_count", "unique_destination_ips",
                        "unique_destination_ports", "tcp_syn_count", "tcp_rst_count"
                    }:
                        flow[key] = int(val)
                flows.append(flow)

            results = state.engine.analyze(flows)
            for result, flow in zip(results["results"], flows):
                result["demo_scenario"] = flow["scenario"]
                result["expected_label"] = flow["expected_label"]

            risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            for result in results["results"]:
                risk_counts[result["fusion"]["risk_level"]] += 1

            await broadcast({
                "type": "network_update",
                "mode": "demo",
                "dataset_name": safe_name,
                "timestamp": time.time(),
                "window_duration": 2,
                "packets_captured": sum(flow["packet_count"] for flow in flows),
                "bytes_captured": sum(int(flow.get("byte_count", 0)) for flow in flows),
                "total_flows": len(results["results"]),
                "anomalies": risk_counts["MEDIUM"] + risk_counts["HIGH"],
                "risk_counts": risk_counts,
                "flows": results["results"]
            })
            await asyncio.sleep(2)
    except Exception as error:
        await broadcast({"type": "error", "message": f"Demo replay failed: {error}"})
    finally:
        if state.mode == "demo":
            state.is_running = False
            state.mode = None
            state.active_dataset = None

@router.get("/health")
def health_check():
    return {
        "api": True,
        "capture": state.is_running,
        "isolation_forest": state.engine.isolation_forest is not None if state.engine else False,
        "gat": state.engine.gat is not None if state.engine else False
    }

@router.get("/status")
def get_status():
    return health_check()

@router.get("/datasets")
def list_datasets():
    """List all available CSV datasets for demo replay with metadata."""
    datasets = []
    for file in sorted(DATA_DIR.glob("*.csv")):
        meta = DATASET_METADATA.get(file.name, {
            "name": file.name.replace("_", " ").replace(".csv", "").title(),
            "description": "Network traffic CSV dataset",
            "category": "other"
        })
        datasets.append({
            "id": file.name,
            "name": meta["name"],
            "description": meta["description"],
            "category": meta["category"]
        })
    return datasets

@router.post("/monitor/start")
async def start_monitor():
    if state.is_running:
        return {"status": "already_running"}
    state.is_running = True
    state.mode = "live"
    state.active_dataset = None
    state.task = asyncio.create_task(capture_loop())
    return {"status": "started"}

@router.post("/monitor/demo")
async def start_demo(
    request: Request,
    dataset: Optional[str] = Query(default=None)
):
    if state.is_running:
        return {"status": "already_running"}
    if state.engine is None:
        return {"status": "engine_unavailable"}

    # Extract dataset from query param or JSON body
    target_dataset = dataset
    if not target_dataset:
        try:
            body = await request.json()
            target_dataset = body.get("dataset")
        except Exception:
            pass

    if not target_dataset:
        target_dataset = DEFAULT_DEMO_DATASET

    state.is_running = True
    state.mode = "demo"
    state.active_dataset = target_dataset
    state.task = asyncio.create_task(demo_loop(target_dataset))
    return {"status": "started", "dataset": target_dataset}

@router.post("/monitor/stop")
async def stop_monitor():
    state.is_running = False
    state.mode = None
    state.active_dataset = None
    return {"status": "stopped"}

@router.get("/monitor/status")
def monitor_status():
    return {
        "is_running": state.is_running,
        "mode": state.mode,
        "active_dataset": state.active_dataset
    }

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in state.active_connections:
            state.active_connections.remove(websocket)

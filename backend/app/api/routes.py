import asyncio
import csv
import time
import math
import urllib.request
from pathlib import Path
from typing import List, Any, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request, Query

from app.capture.packet_capture import flow_processor, process_packet, packet_counter, can_sniff_scapy
import app.capture.packet_capture as pc
from app.capture.system_sniffer import system_sniffer
from app.detection.detection_engine import DetectionEngine
from app.detection.fake_website_detector import fake_website_detector, KNOWN_FAKE_SITES
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
        self.window_size = 3
        self.mode = None
        self.active_dataset = None
        self.capture_mode = None

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

    # Determine initial capture engine capability
    bpf_available = can_sniff_scapy()
    active_mode = "bpf" if bpf_available else "system"
    state.capture_mode = active_mode

    if not bpf_available:
        print("[CAPTURE] Scapy raw BPF requires root privileges. Using Live System Connection Sniffer (Zero-Privilege mode).")
        await broadcast({
            "type": "info",
            "message": "Live System Monitor active (Zero-Privilege). Outbound browser traffic to fake shopping websites (SauceDemo, etc.) is monitored live. To enable raw BPF promiscuous sniffing without root, run: sudo chmod 666 /dev/bpf*"
        })
    else:
        print("[CAPTURE] Using Scapy raw packet sniffing (BPF enabled).")
        await broadcast({
            "type": "info",
            "message": "Raw promiscuous BPF packet capture active."
        })

    while state.is_running:
        captured = 0
        captured_bytes = 0
        flows = []

        if active_mode == "bpf":
            try:
                captured = await asyncio.to_thread(sniff_window, state.window_size)
                flows = flow_processor.get_features()
                flow_processor.clear_flows()
                captured_bytes = sum(int(f.get("byte_count", 0)) for f in flows) if flows else 0

                # Also capture active browser fake website tabs in BPF mode
                browser_flows = system_sniffer.sample_browser_fake_sites()
                if browser_flows:
                    flows.extend(browser_flows)
            except Exception as e:
                # Fallback to system sniffer instead of failing
                print(f"[CAPTURE] Scapy sniff failed ({e}). Falling back to Live System Connection Sniffer.")
                active_mode = "system"
                state.capture_mode = "system"
                await broadcast({
                    "type": "info",
                    "message": "Fell back to Live System Monitor. Outbound connections remain actively monitored."
                })

        if active_mode == "system":
            try:
                captured, captured_bytes, flows = await asyncio.to_thread(
                    system_sniffer.capture_window, state.window_size
                )
            except Exception as e:
                print(f"[CAPTURE] System sniffer error: {e}")
                flows = []

        if not state.is_running:
            break

        if flows:
            results = state.engine.analyze(flows)
        else:
            results = {"total_flows": 0, "anomalies": 0, "results": []}

        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
        for r in results["results"]:
            risk = r.get("fusion", {}).get("risk_level", "LOW")
            if risk in counts:
                counts[risk] += 1

        # Collect any fake website alerts in this window
        fake_site_alerts = [
            {
                "flow": r,
                "fake_website": r["fake_website"]
            }
            for r in results["results"]
            if r.get("fake_website")
        ]

        payload = {
            "type": "network_update",
            "mode": "live",
            "capture_mode": active_mode,
            "timestamp": time.time(),
            "window_duration": state.window_size,
            "packets_captured": captured,
            "bytes_captured": captured_bytes,
            "total_flows": results["total_flows"],
            "anomalies": results["anomalies"],
            "risk_counts": counts,
            "flows": results["results"]
        }

        if fake_site_alerts:
            payload["fake_website_alerts"] = fake_site_alerts

        await broadcast(payload)

    state.mode = None
    state.active_dataset = None
    state.capture_mode = None

# Synthetic fake website demo flows to interleave during demo replay
DEMO_FAKE_SITE_FLOWS = [
    {
        "source_ip": "192.168.1.45",
        "destination_ip": "185.199.111.153",
        "source_port": 52140,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 38,
        "byte_count": 14200,
        "duration": 1.4,
        "packets_per_second": 27.14,
        "bytes_per_second": 10142.8,
        "average_packet_size": 373.68,
        "unique_destination_ips": 1,
        "unique_destination_ports": 1,
        "tcp_syn_count": 1,
        "tcp_rst_count": 0,
        "domain": "saucedemo.com",
        "process": "Google Chrome",
        "scenario": "fake_website_saucedemo",
        "expected_label": "FAKE_WEBSITE_ALERT"
    },
    {
        "source_ip": "192.168.1.45",
        "destination_ip": "104.21.82.30",
        "source_port": 53180,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 42,
        "byte_count": 18400,
        "duration": 1.2,
        "packets_per_second": 35.0,
        "bytes_per_second": 15333.3,
        "average_packet_size": 438.1,
        "unique_destination_ips": 1,
        "unique_destination_ports": 1,
        "tcp_syn_count": 1,
        "tcp_rst_count": 0,
        "domain": "automationexercise.com",
        "process": "Google Chrome",
        "scenario": "fake_website_automation_exercise",
        "expected_label": "FAKE_WEBSITE_ALERT"
    },
    {
        "source_ip": "192.168.1.45",
        "destination_ip": "35.71.177.79",
        "source_port": 54220,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 30,
        "byte_count": 9800,
        "duration": 1.5,
        "packets_per_second": 20.0,
        "bytes_per_second": 6533.3,
        "average_packet_size": 326.6,
        "unique_destination_ips": 1,
        "unique_destination_ports": 1,
        "tcp_syn_count": 1,
        "tcp_rst_count": 0,
        "domain": "the-internet.herokuapp.com",
        "process": "Safari",
        "scenario": "fake_website_the_internet",
        "expected_label": "FAKE_WEBSITE_ALERT"
    },
    {
        "source_ip": "192.168.1.45",
        "destination_ip": "172.66.139.120",
        "source_port": 55300,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 35,
        "byte_count": 12600,
        "duration": 1.1,
        "packets_per_second": 31.8,
        "bytes_per_second": 11454.5,
        "average_packet_size": 360.0,
        "unique_destination_ips": 1,
        "unique_destination_ports": 1,
        "tcp_syn_count": 1,
        "tcp_rst_count": 0,
        "domain": "demo.opencart.com",
        "process": "Google Chrome",
        "scenario": "fake_website_opencart_demo",
        "expected_label": "FAKE_WEBSITE_ALERT"
    },
    {
        "source_ip": "192.168.1.45",
        "destination_ip": "66.241.125.119",
        "source_port": 56420,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 28,
        "byte_count": 11200,
        "duration": 1.3,
        "packets_per_second": 21.5,
        "bytes_per_second": 8615.4,
        "average_packet_size": 400.0,
        "unique_destination_ips": 1,
        "unique_destination_ports": 1,
        "tcp_syn_count": 1,
        "tcp_rst_count": 0,
        "domain": "practice.expandtesting.com",
        "process": "Firefox",
        "scenario": "fake_website_expand_testing",
        "expected_label": "FAKE_WEBSITE_ALERT"
    }
]

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

        fake_site_idx = 0
        batch_idx = 0

        for offset in range(0, len(rows), 7):
            if not state.is_running or state.mode != "demo":
                break

            batch = rows[offset:offset + 7]
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

            # Interleave a fake website demo flow every 2 batches
            if batch_idx % 2 == 1:
                fake_flow = DEMO_FAKE_SITE_FLOWS[fake_site_idx % len(DEMO_FAKE_SITE_FLOWS)].copy()
                fake_site_idx += 1
                flows.append(fake_flow)
            batch_idx += 1

            results = state.engine.analyze(flows)
            for result, flow in zip(results["results"], flows):
                if "demo_scenario" in flow:
                    result["demo_scenario"] = flow["demo_scenario"]
                elif "scenario" in flow:
                    result["demo_scenario"] = flow["scenario"]
                result["expected_label"] = flow.get("expected_label")

            risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            for result in results["results"]:
                risk_counts[result["fusion"]["risk_level"]] += 1

            fake_site_alerts = [
                {
                    "flow": r,
                    "fake_website": r["fake_website"]
                }
                for r in results["results"]
                if r.get("fake_website")
            ]

            payload = {
                "type": "network_update",
                "mode": "demo",
                "capture_mode": "demo",
                "dataset_name": safe_name,
                "timestamp": time.time(),
                "window_duration": 2,
                "packets_captured": sum(flow["packet_count"] for flow in flows),
                "bytes_captured": sum(int(flow.get("byte_count", 0)) for flow in flows),
                "total_flows": len(results["results"]),
                "anomalies": risk_counts["MEDIUM"] + risk_counts["HIGH"],
                "risk_counts": risk_counts,
                "flows": results["results"]
            }

            if fake_site_alerts:
                payload["fake_website_alerts"] = fake_site_alerts

            await broadcast(payload)
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
        "capture_mode": state.capture_mode,
        "bpf_available": can_sniff_scapy(),
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

@router.get("/fake-sites")
def get_fake_sites():
    """Return the registry of fake/demo websites tracked by the detector."""
    return KNOWN_FAKE_SITES

@router.post("/monitor/simulate-fake-site")
async def simulate_fake_site(site_id: str = "saucedemo"):
    """
    Simulates or probes a fake/demo website, injecting a live flow that triggers
    the fake website detector and pop-up alert warning in real time.
    """
    site = next(
        (s for s in fake_website_detector.sites if s["id"] == site_id),
        fake_website_detector.sites[0]
    )
    primary_domain = site["domains"][0]
    primary_ip = site.get("default_ips", ["185.199.111.153"])[0]

    # Try non-blocking real HTTP request in background to generate genuine socket traffic
    def probe():
        try:
            req = urllib.request.Request(
                f"https://{primary_domain}",
                headers={"User-Agent": "Mozilla/5.0 NetworkTrafficVisualizer/1.0"}
            )
            with urllib.request.urlopen(req, timeout=3.0):
                pass
        except Exception:
            pass
    asyncio.create_task(asyncio.to_thread(probe))

    # Form guaranteed flow tuple to inject
    injected_flow = {
        "source_ip": "10.20.185.68",
        "destination_ip": primary_ip,
        "source_port": 54320,
        "destination_port": 443,
        "protocol": "TCP",
        "packet_count": 28,
        "byte_count": 9650,
        "duration": 1.25,
        "packets_per_second": 22.4,
        "bytes_per_second": 7720.0,
        "average_packet_size": 344.6,
        "unique_destination_ips": 1,
        "unique_destination_ports": 1,
        "tcp_syn_count": 1,
        "tcp_rst_count": 0,
        "domain": primary_domain,
        "process": "Google Chrome (Demonstration)",
        "scenario": f"fake_website_{site['id']}",
        "demo_scenario": f"FAKE_WEBSITE_{site['id'].upper()}"
    }

    system_sniffer.inject_flow(injected_flow)

    # If live monitoring is not currently running, broadcast immediate one-shot update
    if not state.is_running:
        analyzed = state.engine.analyze([injected_flow])
        counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 1}
        fake_site_alerts = [
            {
                "flow": analyzed["results"][0],
                "fake_website": analyzed["results"][0].get("fake_website")
            }
        ]
        await broadcast({
            "type": "network_update",
            "mode": "live",
            "capture_mode": "simulation",
            "timestamp": time.time(),
            "window_duration": 2,
            "packets_captured": 28,
            "bytes_captured": 9650,
            "total_flows": 1,
            "anomalies": 1,
            "risk_counts": counts,
            "flows": analyzed["results"],
            "fake_website_alerts": fake_site_alerts
        })

    return {"status": "injected", "site": site["name"], "domain": primary_domain}

@router.post("/monitor/start")
async def start_monitor():
    if state.is_running:
        return {"status": "already_running"}
    state.is_running = True
    state.mode = "live"
    state.active_dataset = None
    state.task = asyncio.create_task(capture_loop())
    return {"status": "started", "capture_mode": state.capture_mode}

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
    state.capture_mode = None
    return {"status": "stopped"}

@router.get("/monitor/status")
def monitor_status():
    return {
        "is_running": state.is_running,
        "mode": state.mode,
        "active_dataset": state.active_dataset,
        "capture_mode": state.capture_mode,
        "bpf_available": can_sniff_scapy()
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

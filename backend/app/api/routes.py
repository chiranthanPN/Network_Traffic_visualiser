import asyncio
import time
import math
from typing import List, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, BackgroundTasks

from app.capture.packet_capture import flow_processor, process_packet, packet_counter
import app.capture.packet_capture as pc
from app.detection.detection_engine import DetectionEngine
from scapy.all import sniff

router = APIRouter(prefix="/api")

class MonitorState:
    def __init__(self):
        self.is_running = False
        self.task = None
        self.engine = None
        self.active_connections: List[WebSocket] = []
        self.window_size = 5

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
            for ws in state.active_connections:
                try:
                    await ws.send_json(error_payload)
                except:
                    pass
            break
        
        if not state.is_running:
            break
            
        flows = flow_processor.get_features()
        flow_processor.clear_flows()
        
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
            "total_flows": results["total_flows"],
            "anomalies": results["anomalies"],
            "risk_counts": counts,
            "flows": results["results"]
        }
        
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

@router.post("/monitor/start")
async def start_monitor():
    if state.is_running:
        return {"status": "already_running"}
    state.is_running = True
    state.task = asyncio.create_task(capture_loop())
    return {"status": "started"}

@router.post("/monitor/stop")
async def stop_monitor():
    state.is_running = False
    return {"status": "stopped"}

@router.get("/monitor/status")
def monitor_status():
    return {"is_running": state.is_running}

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

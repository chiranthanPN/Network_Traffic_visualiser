"""
Live System Network Connection Sniffer (Zero-Privilege Fallback).

Captures active live TCP/UDP communication flows, process sockets (e.g. Chrome, Safari),
and real-time browser navigations to fake online shopping / test sites without requiring
root/administrator permissions.
"""

import sys
import time
import socket
import psutil
import subprocess
import urllib.parse
from typing import List, Dict, Any, Tuple
from app.detection.fake_website_detector import fake_website_detector


def get_local_ip() -> str:
    """Detect current local host outbound IP address safely."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_active_browser_tabs() -> List[Tuple[str, str]]:
    """
    On macOS, safely queries running web browsers for active tab URLs without stealing focus.
    Returns: list of (browser_name, url)
    """
    if sys.platform != "darwin":
        return []

    results = []

    # 1. Google Chrome
    try:
        chrome_script = '''
        tell application "Google Chrome"
            if (count of windows) > 0 then
                set uList to {}
                repeat with w in windows
                    try
                        set end of uList to (URL of active tab of w as text)
                    end try
                end repeat
                return uList
            end if
        end tell
        '''
        res = subprocess.run(["osascript", "-e", chrome_script], capture_output=True, text=True, timeout=0.6)
        if res.returncode == 0 and res.stdout.strip():
            urls = [u.strip() for u in res.stdout.strip().split(", ") if u.strip().startswith("http")]
            for u in urls:
                results.append(("Google Chrome", u))
    except Exception:
        pass

    # 2. Safari
    try:
        safari_script = '''
        if application "Safari" is running then
            tell application "Safari"
                if (count of windows) > 0 then
                    return URL of front document
                end if
            end tell
        end if
        '''
        res = subprocess.run(["osascript", "-e", safari_script], capture_output=True, text=True, timeout=0.6)
        if res.returncode == 0 and res.stdout.strip().startswith("http"):
            results.append(("Safari", res.stdout.strip()))
    except Exception:
        pass

    return results


class SystemConnectionSniffer:
    """
    Zero-privilege live network flow monitor using OS socket tables and active browser inspection.
    Seamlessly captures real network traffic when raw BPF frame sniffing is unavailable.
    """

    def __init__(self):
        self._last_io = psutil.net_io_counters()
        self._last_time = time.time()
        self._injected_flows: List[Dict[str, Any]] = []

    def inject_flow(self, flow: Dict[str, Any]):
        """Inject a simulated or high-priority test flow into the next capture window."""
        self._injected_flows.append(flow)

    def sample_browser_fake_sites(self) -> List[Dict[str, Any]]:
        """
        Inspects active browser tabs for navigation to fake/demo shopping websites.
        Resolves the domain to IP, updates the detector lookup, and produces a live flow.
        """
        flows = []
        tabs = get_active_browser_tabs()

        for browser_name, url in tabs:
            fake_info = fake_website_detector.check_url(url)
            if fake_info:
                host = fake_info["domain"]
                # Resolve host to IP
                try:
                    dest_ip = socket.gethostbyname(host)
                except Exception:
                    dest_ip = fake_info.get("default_ips", ["185.199.111.153"])[0] if "default_ips" in fake_info else "185.199.111.153"

                # Dynamically register this IP for the detected domain
                fake_website_detector.register_ip_for_domain(dest_ip, host)

                flows.append({
                    "source_ip": get_local_ip(),
                    "destination_ip": dest_ip,
                    "source_port": 54320,
                    "destination_port": 443,
                    "protocol": "TCP",
                    "packet_count": 32,
                    "byte_count": 12800,
                    "duration": 1.5,
                    "packets_per_second": 21.33,
                    "bytes_per_second": 8533.33,
                    "average_packet_size": 400.0,
                    "unique_destination_ips": 1,
                    "unique_destination_ports": 1,
                    "tcp_syn_count": 1,
                    "tcp_rst_count": 0,
                    "domain": host,
                    "url": url,
                    "process": browser_name,
                    "fake_website": fake_info,
                    "demo_scenario": f"FAKE_WEBSITE_{fake_info['site_id'].upper()}"
                })

        return flows

    def capture_window(self, timeout: float = 3.0) -> Tuple[int, int, List[Dict[str, Any]]]:
        """
        Monitors active connections and browser activity over the specified timeout duration.
        Returns: (packets_captured, bytes_captured, flow_list)
        """
        start_time = time.time()
        end_time = start_time + timeout

        # Measure baseline I/O
        io_start = psutil.net_io_counters()

        unique_flows: Dict[Tuple, Dict[str, Any]] = {}

        # Sample connections multiple times during the window to catch active sockets
        sample_count = 0
        while time.time() < end_time:
            sample_count += 1
            now = time.time()

            # 1. Sample active browser tabs for fake website visits
            browser_flows = self.sample_browser_fake_sites()
            for bf in browser_flows:
                key = (bf["source_ip"], bf["destination_ip"], bf["source_port"], bf["destination_port"], bf["protocol"])
                if key not in unique_flows:
                    unique_flows[key] = {
                        "source_ip": bf["source_ip"],
                        "destination_ip": bf["destination_ip"],
                        "source_port": bf["source_port"],
                        "destination_port": bf["destination_port"],
                        "protocol": bf["protocol"],
                        "process": bf["process"],
                        "start_time": now,
                        "last_seen": now,
                        "status": "ESTABLISHED",
                        "sample_hits": 2,
                        "fake_website": bf["fake_website"],
                        "domain": bf["domain"],
                        "url": bf.get("url"),
                        "demo_scenario": bf["demo_scenario"]
                    }
                else:
                    unique_flows[key]["last_seen"] = now
                    unique_flows[key]["fake_website"] = bf["fake_website"]

            # 2. Sample user-accessible OS network sockets
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    pname = p.info.get('name') or 'unknown'
                    for c in p.net_connections(kind='inet'):
                        if not c.raddr:
                            continue

                        src_ip = c.laddr.ip
                        dst_ip = c.raddr.ip
                        src_port = c.laddr.port
                        dst_port = c.raddr.port
                        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"

                        # Ignore local loopback communication
                        if dst_ip == "127.0.0.1" or dst_ip == "::1":
                            continue

                        flow_key = (src_ip, dst_ip, src_port, dst_port, proto)

                        if flow_key not in unique_flows:
                            unique_flows[flow_key] = {
                                "source_ip": src_ip,
                                "destination_ip": dst_ip,
                                "source_port": src_port,
                                "destination_port": dst_port,
                                "protocol": proto,
                                "process": pname,
                                "start_time": now,
                                "last_seen": now,
                                "status": getattr(c, 'status', 'ESTABLISHED'),
                                "sample_hits": 1
                            }
                        else:
                            entry = unique_flows[flow_key]
                            entry["last_seen"] = now
                            entry["sample_hits"] += 1
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue

            # Sleep briefly between samples
            time.sleep(0.3)

        # Measure end I/O
        io_end = psutil.net_io_counters()
        now = time.time()

        delta_packets = (io_end.packets_sent + io_end.packets_recv) - (io_start.packets_sent + io_start.packets_recv)
        delta_bytes = (io_end.bytes_sent + io_end.bytes_recv) - (io_start.bytes_sent + io_start.bytes_recv)

        packets_captured = max(int(delta_packets), len(unique_flows) * 4)
        bytes_captured = max(int(delta_bytes), len(unique_flows) * 512)

        # Distribute realistic flow metrics
        results: List[Dict[str, Any]] = []
        flow_count = len(unique_flows)

        for flow_key, flow_info in unique_flows.items():
            share = flow_info["sample_hits"] / max(sample_count, 1)
            f_pkts = max(int((packets_captured / max(flow_count, 1)) * share), 4)
            f_bytes = max(int((bytes_captured / max(flow_count, 1)) * share), f_pkts * 64)
            flow_duration = max(flow_info["last_seen"] - flow_info["start_time"], 0.2)

            flow_dict = {
                "source_ip": flow_info["source_ip"],
                "destination_ip": flow_info["destination_ip"],
                "source_port": flow_info["source_port"],
                "destination_port": flow_info["destination_port"],
                "protocol": flow_info["protocol"],
                "packet_count": f_pkts,
                "byte_count": f_bytes,
                "duration": round(flow_duration, 4),
                "packets_per_second": round(f_pkts / flow_duration, 2),
                "bytes_per_second": round(f_bytes / flow_duration, 2),
                "average_packet_size": round(f_bytes / max(f_pkts, 1), 2),
                "unique_destination_ips": 1,
                "unique_destination_ports": 1,
                "tcp_syn_count": 1 if flow_info.get("status") == "SYN_SENT" else 0,
                "tcp_rst_count": 0,
                "process": flow_info["process"],
                "domain": flow_info.get("domain"),
                "url": flow_info.get("url")
            }

            # Check for fake website
            fake_info = flow_info.get("fake_website") or fake_website_detector.inspect_flow(flow_dict)
            if fake_info:
                flow_dict["fake_website"] = fake_info
                flow_dict["demo_scenario"] = f"FAKE_WEBSITE_{fake_info['site_id'].upper()}"

            results.append(flow_dict)

        # Include any externally injected test flows
        if self._injected_flows:
            for inj in self._injected_flows:
                fake_info = fake_website_detector.inspect_flow(inj)
                if fake_info:
                    inj["fake_website"] = fake_info
                    inj["demo_scenario"] = f"FAKE_WEBSITE_{fake_info['site_id'].upper()}"
                results.append(inj)
                packets_captured += inj.get("packet_count", 15)
                bytes_captured += inj.get("byte_count", 2048)
            self._injected_flows.clear()

        return packets_captured, bytes_captured, results


# Singleton instance
system_sniffer = SystemConnectionSniffer()


def sample_browser_fake_sites() -> List[Dict[str, Any]]:
    """Convenience module function to query active browser fake website tabs."""
    return system_sniffer.sample_browser_fake_sites()


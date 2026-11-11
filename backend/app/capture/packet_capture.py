import os
from scapy.all import sniff, IP, TCP, UDP, Raw

from app.features.feature_extractor import FlowProcessor
from app.features.data_collector import save_features
from app.detection.fake_website_detector import fake_website_detector


def can_sniff_scapy() -> bool:
    """Check if Scapy raw packet sniffing has appropriate OS permissions."""
    try:
        if os.name != "nt" and os.path.exists("/dev/bpf0"):
            if not (os.access("/dev/bpf0", os.R_OK) and os.access("/dev/bpf0", os.W_OK)):
                return False
        # Quick non-blocking probe
        sniff(count=1, timeout=0.05, store=False)
        return True
    except Exception:
        return False


def parse_tls_sni(payload: bytes):
    """Extract Server Name Indication (SNI) from TLS Client Hello packets."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        session_id_len = payload[43]
        idx = 44 + session_id_len
        if idx + 2 > len(payload):
            return None
        cipher_suites_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2 + cipher_suites_len
        if idx + 1 > len(payload):
            return None
        comp_methods_len = payload[idx]
        idx += 1 + comp_methods_len
        if idx + 2 > len(payload):
            return None
        exts_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2
        end_exts = idx + exts_len
        while idx + 4 <= end_exts and idx + 4 <= len(payload):
            ext_type = int.from_bytes(payload[idx:idx + 2], "big")
            ext_len = int.from_bytes(payload[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0 and idx + 5 <= len(payload):
                name_len = int.from_bytes(payload[idx + 3:idx + 5], "big")
                return payload[idx + 5:idx + 5 + name_len].decode("utf-8", errors="ignore")
            idx += ext_len
    except Exception:
        pass
    return None


# ============================================================
# FLOW PROCESSOR
# ============================================================

flow_processor = FlowProcessor(window_size=5)


# Count packets in the current 5-second window
packet_counter = 0


# ============================================================
# PACKET PROCESSING
# ============================================================

def process_packet(packet):

    global packet_counter

    # We only process IPv4 packets
    if IP not in packet:
        return

    packet_counter += 1

    # --------------------------------------------------------
    # Basic IP information
    # --------------------------------------------------------

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)

    # --------------------------------------------------------
    # Default values
    # --------------------------------------------------------

    protocol = "OTHER"

    source_port = None
    destination_port = None

    tcp_syn = False
    tcp_rst = False

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if TCP in packet:

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        # TCP flags
        flags = packet[TCP].flags

        tcp_syn = "S" in flags
        tcp_rst = "R" in flags

        # Inspect TLS SNI for fake website detection
        if Raw in packet:
            try:
                payload = bytes(packet[Raw])
                sni = parse_tls_sni(payload)
                if sni:
                    fake_website_detector.register_ip_for_domain(destination_ip, sni)
            except Exception:
                pass

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    elif UDP in packet:

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # --------------------------------------------------------
    # Add packet to FlowProcessor
    # --------------------------------------------------------

    flow_processor.process_packet(

        source_ip=source_ip,

        destination_ip=destination_ip,

        protocol=protocol,

        packet_size=packet_size,

        source_port=source_port,

        destination_port=destination_port,

        tcp_syn=tcp_syn,

        tcp_rst=tcp_rst
    )


# ============================================================
# DISPLAY FLOW FEATURES
# ============================================================

def print_features():

    print("\n")

    print("=" * 70)

    print("NETWORK TRAFFIC ANALYSIS")

    print("=" * 70)

    print(
        f"Packets captured: {packet_counter}"
    )

    # Get features from current window
    features = flow_processor.get_features()

    # --------------------------------------------------------
    # No traffic
    # --------------------------------------------------------

    if not features:

        print(
            "\nNo IP traffic captured in this window."
        )

    # --------------------------------------------------------
    # Display flows
    # --------------------------------------------------------

    else:

        for index, feature in enumerate(
            features,
            start=1
        ):

            print("\n" + "-" * 70)

            print(
                f"FLOW {index}"
            )

            print("-" * 70)

            print(
                f"Source IP:              "
                f"{feature['source_ip']}"
            )

            print(
                f"Destination IP:         "
                f"{feature['destination_ip']}"
            )

            print(
                f"Source Port:            "
                f"{feature['source_port']}"
            )

            print(
                f"Destination Port:       "
                f"{feature['destination_port']}"
            )

            print(
                f"Protocol:               "
                f"{feature['protocol']}"
            )

            print(
                f"Packet Count:           "
                f"{feature['packet_count']}"
            )

            print(
                f"Byte Count:             "
                f"{feature['byte_count']}"
            )

            print(
                f"Duration:               "
                f"{feature['duration']:.4f} seconds"
            )

            print(
                f"Packets/sec:            "
                f"{feature['packets_per_second']:.2f}"
            )

            print(
                f"Bytes/sec:              "
                f"{feature['bytes_per_second']:.2f}"
            )

            print(
                f"Average Packet Size:    "
                f"{feature['average_packet_size']:.2f} bytes"
            )

            print(
                f"Unique Destination IPs: "
                f"{feature['unique_destination_ips']}"
            )

            print(
                f"Unique Destination Ports:"
                f" {feature['unique_destination_ports']}"
            )

            print(
                f"TCP SYN Count:          "
                f"{feature['tcp_syn_count']}"
            )

            print(
                f"TCP RST Count:          "
                f"{feature['tcp_rst_count']}"
            )

    print("=" * 70)


# ============================================================
# START PACKET CAPTURE
# ============================================================

def start_capture():

    global packet_counter

    print(
        "Starting network packet capture..."
    )

    print(
        "Real-time 5-second flow analysis"
    )

    print(
        "Press Ctrl+C to stop."
    )

    print()

    try:

        while True:

            # ------------------------------------------------
            # Start a new 5-second window
            # ------------------------------------------------

            packet_counter = 0

            print(
                "Capturing next 5-second window..."
            )

            # ------------------------------------------------
            # Capture packets for 5 seconds
            # ------------------------------------------------

            sniff(

                prn=process_packet,

                store=False,

                timeout=5
            )
            # Get features from current window

            features = flow_processor.get_features()


            # ------------------------------------------------
            # Display current window
            # ------------------------------------------------

            print_features()

            # Save features for Isolation Forest training

            save_features(features)


            # ------------------------------------------------
            # Clear flows before next window
            # ------------------------------------------------

            flow_processor.clear_flows()

    except KeyboardInterrupt:

        print(
            "\nStopping network traffic analyzer..."
        )

        # Display the final window
        print_features()


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    start_capture()
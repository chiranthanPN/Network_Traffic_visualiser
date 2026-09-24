import time

from scapy.all import sniff, IP, TCP, UDP

from app.features.feature_extractor import FlowProcessor
from app.detection.detection_engine import DetectionEngine


# =================================================================
# CONFIGURATION
# =================================================================

WINDOW_SIZE = 5


# =================================================================
# GLOBAL OBJECTS
# =================================================================

flow_processor = FlowProcessor(
    window_size=WINDOW_SIZE
)

detection_engine = None

packet_counter = 0


# =================================================================
# PACKET PROCESSING
# =================================================================

def process_packet(packet):

    global packet_counter

    # -------------------------------------------------------------
    # Ignore packets without IP layer
    # -------------------------------------------------------------

    if IP not in packet:
        return

    packet_counter += 1

    # -------------------------------------------------------------
    # Basic packet information
    # -------------------------------------------------------------

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    packet_size = len(packet)

    protocol = "OTHER"

    source_port = None
    destination_port = None

    tcp_syn = False
    tcp_rst = False

    # -------------------------------------------------------------
    # TCP
    # -------------------------------------------------------------

    if TCP in packet:

        protocol = "TCP"

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

        flags = packet[TCP].flags

        tcp_syn = "S" in flags
        tcp_rst = "R" in flags

    # -------------------------------------------------------------
    # UDP
    # -------------------------------------------------------------

    elif UDP in packet:

        protocol = "UDP"

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # -------------------------------------------------------------
    # Add packet to flow processor
    # -------------------------------------------------------------

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


# =================================================================
# PRINT WINDOW HEADER
# =================================================================

def print_window_header(window_number):

    print("\n")
    print("=" * 80)
    print(
        f"LIVE NETWORK TRAFFIC ANALYSIS - WINDOW {window_number}"
    )
    print("=" * 80)


# =================================================================
# PRINT FLOW INFORMATION
# =================================================================

def print_flow_result(
    index,
    result
):

    print("\n" + "-" * 80)

    print(
        f"FLOW {index}"
    )

    print(
        f"Source IP:          "
        f"{result['source_ip']}"
    )

    print(
        f"Destination IP:     "
        f"{result['destination_ip']}"
    )

    print(
        f"Source Port:        "
        f"{result['source_port']}"
    )

    print(
        f"Destination Port:   "
        f"{result['destination_port']}"
    )

    print(
        f"Protocol:           "
        f"{result['protocol']}"
    )

    print(
        f"Packets:            "
        f"{result['packet_count']}"
    )

    print(
        f"Bytes:              "
        f"{result['byte_count']}"
    )

    # -------------------------------------------------------------
    # Isolation Forest
    # -------------------------------------------------------------

    isolation = result[
        "isolation_forest"
    ]

    print("\nIsolation Forest:")

    print(
        f"  Anomaly:          "
        f"{isolation['is_anomaly']}"
    )

    print(
        f"  Decision score:   "
        f"{isolation['decision_score']:.4f}"
    )

    # -------------------------------------------------------------
    # GAT
    # -------------------------------------------------------------

    gat = result[
        "gat"
    ]

    print("\nGAT:")

    print(
        f"  Anomaly:          "
        f"{gat['is_anomaly']}"
    )

    print(
        f"  Attack score:     "
        f"{gat['attack_score']:.4f}"
    )

    print(
        f"  Threshold:        "
        f"{gat['threshold']:.2f}"
    )

    # -------------------------------------------------------------
    # Fusion
    # -------------------------------------------------------------

    fusion = result[
        "fusion"
    ]

    print("\nFusion:")

    print(
        f"  Isolation Forest: "
        f"{fusion['isolation_forest_anomaly']}"
    )

    print(
        f"  GAT:              "
        f"{fusion['gat_anomaly']}"
    )

    print(
        f"  Risk Level:       "
        f"{fusion['risk_level']}"
    )


# =================================================================
# PRINT WINDOW SUMMARY
# =================================================================

def print_summary(
    results,
    elapsed_time
):

    print("\n")
    print("=" * 80)
    print("WINDOW SUMMARY")
    print("=" * 80)

    print(
        f"Packets captured:   "
        f"{packet_counter}"
    )

    print(
        f"Flows analyzed:     "
        f"{results['total_flows']}"
    )

    print(
        f"Anomalies:          "
        f"{results['anomalies']}"
    )

    # -------------------------------------------------------------
    # Count risk levels
    # -------------------------------------------------------------

    low_count = 0
    medium_count = 0
    high_count = 0

    for result in results["results"]:

        risk = result[
            "fusion"
        ][
            "risk_level"
        ]

        if risk == "LOW":
            low_count += 1

        elif risk == "MEDIUM":
            medium_count += 1

        elif risk == "HIGH":
            high_count += 1

    print(
        f"Low risk flows:     "
        f"{low_count}"
    )

    print(
        f"Medium risk flows:  "
        f"{medium_count}"
    )

    print(
        f"High risk flows:    "
        f"{high_count}"
    )

    print(
        f"Processing time:    "
        f"{elapsed_time:.2f} seconds"
    )

    print("=" * 80)


# =================================================================
# START LIVE DETECTION
# =================================================================

def start_live_detection():

    global detection_engine
    global packet_counter

    # -------------------------------------------------------------
    # Initialize AI engine
    # -------------------------------------------------------------

    print("\n")

    print("=" * 80)
    print("NETWORK TRAFFIC VISUALIZER AND ANALYZER")
    print("=" * 80)

    print("\nInitializing AI detection system...")

    detection_engine = DetectionEngine()

    print("\nAI detection system ready.")

    print("\n")
    print("=" * 80)
    print("REAL-TIME DETECTION STARTED")
    print("=" * 80)

    print(
        f"Analysis window: {WINDOW_SIZE} seconds"
    )

    print(
        "Press Ctrl+C to stop."
    )

    print("=" * 80)

    window_number = 0

    try:

        while True:

            window_number += 1

            # -----------------------------------------------------
            # Reset packet counter
            # -----------------------------------------------------

            packet_counter = 0

            # -----------------------------------------------------
            # Start window
            # -----------------------------------------------------

            print_window_header(
                window_number
            )

            print(
                "\nCapturing network traffic..."
            )

            print(
                f"Window duration: "
                f"{WINDOW_SIZE} seconds"
            )

            # -----------------------------------------------------
            # Capture packets
            # -----------------------------------------------------

            sniff(
                prn=process_packet,
                store=False,
                timeout=WINDOW_SIZE
            )

            print(
                "\nPacket capture complete."
            )

            # -----------------------------------------------------
            # Get flow features
            # -----------------------------------------------------

            flows = flow_processor.get_features()

            if not flows:

                print(
                    "\nNo IP flows detected "
                    "during this window."
                )

                flow_processor.clear_flows()

                continue

            # -----------------------------------------------------
            # Run complete AI pipeline
            # -----------------------------------------------------

            print(
                f"\nAnalyzing {len(flows)} flows..."
            )

            start_time = time.time()

            results = detection_engine.analyze(
                flows
            )

            elapsed_time = (
                time.time() - start_time
            )

            # -----------------------------------------------------
            # Display individual results
            # -----------------------------------------------------

            for index, result in enumerate(
                results["results"],
                start=1
            ):

                print_flow_result(
                    index,
                    result
                )

            # -----------------------------------------------------
            # Display summary
            # -----------------------------------------------------

            print_summary(
                results,
                elapsed_time
            )

            # -----------------------------------------------------
            # Clear flows for next window
            # -----------------------------------------------------

            flow_processor.clear_flows()

    except KeyboardInterrupt:

        print("\n")
        print("=" * 80)
        print("STOPPING LIVE DETECTION")
        print("=" * 80)

        print(
            "Network traffic analyzer stopped."
        )


# =================================================================
# MAIN
# =================================================================

if __name__ == "__main__":

    start_live_detection()
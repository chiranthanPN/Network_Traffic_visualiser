from collections import defaultdict
import time


class FlowProcessor:

    def __init__(self, window_size=5):

        self.window_size = window_size

        self.flows = defaultdict(self._create_flow)

        self.window_start = time.time()

    # ========================================================
    # CREATE EMPTY FLOW
    # ========================================================

    def _create_flow(self):

        return {
            "packet_count": 0,

            "byte_count": 0,

            "start_time": None,

            "end_time": None,

            "destination_ips": set(),

            "destination_ports": set(),

            "tcp_syn_count": 0,

            "tcp_rst_count": 0
        }

    # ========================================================
    # PROCESS PACKET
    # ========================================================

    def process_packet(
        self,
        source_ip,
        destination_ip,
        protocol,
        packet_size,
        source_port=None,
        destination_port=None,
        tcp_syn=False,
        tcp_rst=False
    ):

        # ----------------------------------------------------
        # Flow identifier
        #
        # A flow is identified by:
        #
        # Source IP
        # Destination IP
        # Source Port
        # Destination Port
        # Protocol
        # ----------------------------------------------------

        flow_key = (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol
        )

        current_time = time.time()

        flow = self.flows[flow_key]

        # ----------------------------------------------------
        # First packet of this flow
        # ----------------------------------------------------

        if flow["start_time"] is None:

            flow["start_time"] = current_time

        # Update last packet time

        flow["end_time"] = current_time

        # ----------------------------------------------------
        # Packet statistics
        # ----------------------------------------------------

        flow["packet_count"] += 1

        flow["byte_count"] += packet_size

        # ----------------------------------------------------
        # Destination information
        # ----------------------------------------------------

        flow["destination_ips"].add(
            destination_ip
        )

        if destination_port is not None:

            flow["destination_ports"].add(
                destination_port
            )

        # ----------------------------------------------------
        # TCP flags
        # ----------------------------------------------------

        if tcp_syn:

            flow["tcp_syn_count"] += 1

        if tcp_rst:

            flow["tcp_rst_count"] += 1

    # ========================================================
    # GENERATE FEATURES
    # ========================================================

    def get_features(self):

        results = []

        # ----------------------------------------------------
        # Process every flow
        # ----------------------------------------------------

        for (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol
        ), flow in self.flows.items():

            # Skip incomplete flows

            if flow["start_time"] is None:

                continue

            # ------------------------------------------------
            # Calculate duration
            # ------------------------------------------------

            duration = (
                flow["end_time"]
                -
                flow["start_time"]
            )

            # Prevent division by zero

            duration = max(
                duration,
                0.001
            )

            # ------------------------------------------------
            # Basic statistics
            # ------------------------------------------------

            packet_count = flow["packet_count"]

            byte_count = flow["byte_count"]

            # ------------------------------------------------
            # Packets per second
            # ------------------------------------------------

            packets_per_second = (
                packet_count / duration
            )

            # ------------------------------------------------
            # Bytes per second
            # ------------------------------------------------

            bytes_per_second = (
                byte_count / duration
            )

            # ------------------------------------------------
            # Average packet size
            # ------------------------------------------------

            if packet_count > 0:

                average_packet_size = (
                    byte_count / packet_count
                )

            else:

                average_packet_size = 0

            # ------------------------------------------------
            # Store extracted features
            # ------------------------------------------------

            results.append({

                "source_ip":
                    source_ip,

                "destination_ip":
                    destination_ip,

                "source_port":
                    source_port,

                "destination_port":
                    destination_port,

                "protocol":
                    protocol,

                "packet_count":
                    packet_count,

                "byte_count":
                    byte_count,

                "duration":
                    duration,

                "packets_per_second":
                    packets_per_second,

                "bytes_per_second":
                    bytes_per_second,

                "average_packet_size":
                    average_packet_size,

                "unique_destination_ips":
                    len(
                        flow["destination_ips"]
                    ),

                "unique_destination_ports":
                    len(
                        flow["destination_ports"]
                    ),

                "tcp_syn_count":
                    flow["tcp_syn_count"],

                "tcp_rst_count":
                    flow["tcp_rst_count"]
            })

        return results

    # ========================================================
    # CLEAR CURRENT WINDOW
    # ========================================================

    def clear_flows(self):

        self.flows.clear()

        self.window_start = time.time()
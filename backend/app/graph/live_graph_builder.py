import torch


class LiveGraphBuilder:
    """
    Converts live flow features into a graph representation
    compatible with the GAT model.

    Nodes:
        Unique IP addresses

    Edges:
        Source IP -> Destination IP

    Node features:
        Same 14 features used during GAT training.
    """

    FEATURE_NAMES = [
        "flow_count",
        "outbound_flows",
        "inbound_flows",
        "outbound_packets",
        "inbound_packets",
        "outbound_bytes",
        "inbound_bytes",
        "average_duration",
        "average_bytes_per_second",
        "average_packets_per_second",
        "average_packet_size",
        "tcp_flows",
        "udp_flows",
        "unique_peers"
    ]

    def __init__(self):
        pass

    def build(self, flows):

        if not flows:
            return None

        # ---------------------------------------------------------
        # Collect unique IP addresses
        # ---------------------------------------------------------
        ip_set = set()

        for flow in flows:
            source_ip = flow.get("source_ip")
            destination_ip = flow.get("destination_ip")

            if source_ip:
                ip_set.add(source_ip)

            if destination_ip:
                ip_set.add(destination_ip)

        ip_list = sorted(ip_set)

        ip_to_index = {
            ip: index
            for index, ip in enumerate(ip_list)
        }

        # ---------------------------------------------------------
        # Node statistics
        # ---------------------------------------------------------
        nodes = {
            ip: {
                "flow_count": 0,
                "outbound_flows": 0,
                "inbound_flows": 0,
                "outbound_packets": 0,
                "inbound_packets": 0,
                "outbound_bytes": 0,
                "inbound_bytes": 0,
                "durations": [],
                "bytes_per_second": [],
                "packets_per_second": [],
                "packet_sizes": [],
                "tcp_flows": 0,
                "udp_flows": 0,
                "peers": set()
            }
            for ip in ip_list
        }

        # ---------------------------------------------------------
        # Build node statistics from flows
        # ---------------------------------------------------------
        for flow in flows:

            source_ip = flow.get("source_ip")
            destination_ip = flow.get("destination_ip")

            if not source_ip or not destination_ip:
                continue

            packet_count = float(
                flow.get("packet_count", 0)
            )

            byte_count = float(
                flow.get("byte_count", 0)
            )

            duration = float(
                flow.get("duration", 0)
            )

            bytes_per_second = float(
                flow.get("bytes_per_second", 0)
            )

            packets_per_second = float(
                flow.get("packets_per_second", 0)
            )

            average_packet_size = float(
                flow.get("average_packet_size", 0)
            )

            protocol = str(
                flow.get("protocol", "")
            ).upper()

            # -----------------------------------------------------
            # Source node
            # -----------------------------------------------------
            source = nodes[source_ip]

            source["flow_count"] += 1
            source["outbound_flows"] += 1
            source["outbound_packets"] += packet_count
            source["outbound_bytes"] += byte_count

            source["durations"].append(duration)
            source["bytes_per_second"].append(
                bytes_per_second
            )
            source["packets_per_second"].append(
                packets_per_second
            )
            source["packet_sizes"].append(
                average_packet_size
            )

            source["peers"].add(destination_ip)

            if protocol == "TCP":
                source["tcp_flows"] += 1

            elif protocol == "UDP":
                source["udp_flows"] += 1

            # -----------------------------------------------------
            # Destination node
            # -----------------------------------------------------
            destination = nodes[destination_ip]

            destination["flow_count"] += 1
            destination["inbound_flows"] += 1
            destination["inbound_packets"] += packet_count
            destination["inbound_bytes"] += byte_count

            destination["durations"].append(duration)
            destination["bytes_per_second"].append(
                bytes_per_second
            )
            destination["packets_per_second"].append(
                packets_per_second
            )
            destination["packet_sizes"].append(
                average_packet_size
            )

            destination["peers"].add(source_ip)

            if protocol == "TCP":
                destination["tcp_flows"] += 1

            elif protocol == "UDP":
                destination["udp_flows"] += 1

        # ---------------------------------------------------------
        # Create node feature matrix
        # ---------------------------------------------------------
        node_features = []

        for ip in ip_list:

            node = nodes[ip]

            durations = node["durations"]
            bytes_per_second = node["bytes_per_second"]
            packets_per_second = node["packets_per_second"]
            packet_sizes = node["packet_sizes"]

            average_duration = (
                sum(durations) / len(durations)
                if durations
                else 0.0
            )

            average_bps = (
                sum(bytes_per_second)
                / len(bytes_per_second)
                if bytes_per_second
                else 0.0
            )

            average_pps = (
                sum(packets_per_second)
                / len(packets_per_second)
                if packets_per_second
                else 0.0
            )

            average_packet_size = (
                sum(packet_sizes)
                / len(packet_sizes)
                if packet_sizes
                else 0.0
            )

            features = [
                node["flow_count"],
                node["outbound_flows"],
                node["inbound_flows"],
                node["outbound_packets"],
                node["inbound_packets"],
                node["outbound_bytes"],
                node["inbound_bytes"],
                average_duration,
                average_bps,
                average_pps,
                average_packet_size,
                node["tcp_flows"],
                node["udp_flows"],
                len(node["peers"])
            ]

            node_features.append(features)

        # ---------------------------------------------------------
        # Create edge index
        # ---------------------------------------------------------
        edges = []

        for flow in flows:

            source_ip = flow.get("source_ip")
            destination_ip = flow.get("destination_ip")

            if (
                source_ip not in ip_to_index
                or destination_ip not in ip_to_index
            ):
                continue

            source_index = ip_to_index[source_ip]
            destination_index = ip_to_index[destination_ip]

            edges.append(
                [source_index, destination_index]
            )

        # Remove duplicate edges
        edges = list(
            dict.fromkeys(
                (source, destination)
                for source, destination in edges
            )
        )

        # ---------------------------------------------------------
        # Convert to tensors
        # ---------------------------------------------------------
        x = torch.tensor(
            node_features,
            dtype=torch.float32
        )

        if edges:

            edge_index = torch.tensor(
                edges,
                dtype=torch.long
            ).t().contiguous()

        else:

            edge_index = torch.empty(
                (2, 0),
                dtype=torch.long
            )

        return {
            "x": x,
            "edge_index": edge_index,
            "index_to_ip": ip_list,
            "ip_to_index": ip_to_index,
            "num_nodes": len(ip_list),
            "num_edges": edge_index.shape[1],
            "feature_names": self.FEATURE_NAMES
        }


# -----------------------------------------------------------------
# Simple test
# -----------------------------------------------------------------
if __name__ == "__main__":

    builder = LiveGraphBuilder()

    test_flows = [
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "packet_count": 10,
            "byte_count": 1000,
            "duration": 1.0,
            "packets_per_second": 10.0,
            "bytes_per_second": 1000.0,
            "average_packet_size": 100.0
        },
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "1.1.1.1",
            "protocol": "TCP",
            "packet_count": 5,
            "byte_count": 500,
            "duration": 2.0,
            "packets_per_second": 2.5,
            "bytes_per_second": 250.0,
            "average_packet_size": 100.0
        }
    ]

    graph = builder.build(test_flows)

    print("=" * 70)
    print("LIVE GRAPH BUILDER TEST")
    print("=" * 70)

    print(f"Nodes: {graph['num_nodes']}")
    print(f"Edges: {graph['num_edges']}")
    print(f"Feature shape: {graph['x'].shape}")
    print(f"Edge shape: {graph['edge_index'].shape}")

    print("\nIPs:")
    for index, ip in enumerate(graph["index_to_ip"]):
        print(index, ip)

    print("\nNode features:")
    print(graph["x"])

    print("\nEdge index:")
    print(graph["edge_index"])

    print("=" * 70)
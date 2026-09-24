import pandas as pd
import torch

from pathlib import Path


# =========================================================
# PATHS
# =========================================================

DATASET_DIR = Path(
    "data/gat/generated_flows"
)

OUTPUT_FILE = Path(
    "data/gat/gat_graph_leakage_safe.pt"
)


# =========================================================
# SPLIT SETTINGS
# Must remain identical throughout the project
# =========================================================

RANDOM_SEED = 42

TRAIN_RATIO = 0.80
VAL_RATIO = 0.10


# =========================================================
# NODE FEATURES
# =========================================================

NODE_FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size",
]


# =========================================================
# SAFE NUMERIC CONVERSION
# =========================================================

def safe_numeric(series):

    values = pd.to_numeric(
        series,
        errors="coerce"
    )

    values = values.replace(
        [float("inf"), float("-inf")],
        0
    )

    return values.fillna(0)


# =========================================================
# NODE STATISTICS
# =========================================================

def create_node_statistics():

    return {
        "flow_count": 0,

        "outbound_flows": 0,
        "inbound_flows": 0,

        "outbound_packets": 0.0,
        "inbound_packets": 0.0,

        "outbound_bytes": 0.0,
        "inbound_bytes": 0.0,

        "duration_sum": 0.0,

        "bytes_per_second_sum": 0.0,
        "packets_per_second_sum": 0.0,

        "packet_size_sum": 0.0,

        "tcp_flows": 0,
        "udp_flows": 0,

        "peers": set()
    }


# =========================================================
# MAIN
# =========================================================

def build_graph():

    print("=" * 70)
    print("BUILDING LEAKAGE-SAFE CIC-IDS2017 GAT GRAPH")
    print("=" * 70)

    files = sorted(
        DATASET_DIR.rglob("*.csv")
    )

    print(
        f"\nCSV files found: {len(files)}"
    )

    if not files:

        raise FileNotFoundError(
            f"No CSV files found in {DATASET_DIR}"
        )

    # =====================================================
    # STEP 1
    #
    # Collect unique communication edges
    # =====================================================

    print(
        "\nSTEP 1: Collecting communication edges..."
    )

    edge_statistics = {}

    ip_set = set()

    total_flows = 0

    for file_index, file in enumerate(
        files,
        start=1
    ):

        print(
            f"\n[{file_index}/{len(files)}] "
            f"Reading {file.name}"
        )

        df = pd.read_csv(
            file,
            encoding="latin1",
            low_memory=False
        )

        df.columns = (
            df.columns
            .str.strip()
        )

        required_columns = [
            "Source IP",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Label"
        ]

        missing_columns = [
            column
            for column in required_columns
            if column not in df.columns
        ]

        if missing_columns:

            raise ValueError(
                f"Missing columns in "
                f"{file.name}: "
                f"{missing_columns}"
            )

        df = df.dropna(
            subset=[
                "Source IP",
                "Destination IP",
                "Label"
            ]
        )

        print(
            f"    Valid flows: {len(df):,}"
        )

        total_flows += len(df)

        # -------------------------------------------------
        # Numeric conversion
        # -------------------------------------------------

        df["Destination Port"] = safe_numeric(
            df["Destination Port"]
        )

        df["Protocol"] = safe_numeric(
            df["Protocol"]
        )

        # -------------------------------------------------
        # Only columns needed for edge construction
        # -------------------------------------------------

        for row in df[
            [
                "Source IP",
                "Destination IP",
                "Destination Port",
                "Protocol",
                "Label"
            ]
        ].itertuples(
            index=False,
            name=None
        ):

            source_ip = str(
                row[0]
            ).strip()

            destination_ip = str(
                row[1]
            ).strip()

            destination_port = int(
                row[2]
            )

            protocol = int(
                row[3]
            )

            label = str(
                row[4]
            ).strip()

            if (
                source_ip.lower() == "nan"
                or destination_ip.lower() == "nan"
            ):
                continue

            # -------------------------------------------------
            # Register IPs
            # -------------------------------------------------

            ip_set.add(
                source_ip
            )

            ip_set.add(
                destination_ip
            )

            # -------------------------------------------------
            # Edge identity
            #
            # Source IP
            # Destination IP
            # Destination Port
            # Protocol
            # -------------------------------------------------

            edge_key = (
                source_ip,
                destination_ip,
                destination_port,
                protocol
            )

            if edge_key not in edge_statistics:

                edge_statistics[
                    edge_key
                ] = {
                    "attack_count": 0,
                    "benign_count": 0,
                    "flow_count": 0
                }

            edge = edge_statistics[
                edge_key
            ]

            edge[
                "flow_count"
            ] += 1

            if label.upper() == "BENIGN":

                edge[
                    "benign_count"
                ] += 1

            else:

                edge[
                    "attack_count"
                ] += 1

        del df

    # =====================================================
    # STEP 2
    #
    # Create node mapping
    # =====================================================

    print(
        "\nSTEP 2: Creating node mapping..."
    )

    sorted_ips = sorted(
        ip_set
    )

    ip_to_index = {
        ip: index
        for index, ip
        in enumerate(sorted_ips)
    }

    index_to_ip = {
        index: ip
        for ip, index
        in ip_to_index.items()
    }

    num_nodes = len(
        ip_to_index
    )

    print(
        f"Nodes: {num_nodes:,}"
    )

    # =====================================================
    # STEP 3
    #
    # Convert edges into tensors
    # =====================================================

    print(
        "\nSTEP 3: Creating edge tensors..."
    )

    edge_keys = sorted(
        edge_statistics.keys()
)
    

    edge_pairs = []

    edge_labels = []

    edge_ports = []

    edge_protocols = []

    for (
        source_ip,
        destination_ip,
        destination_port,
        protocol
    ) in edge_keys:

        edge_pairs.append(
            [
                ip_to_index[
                    source_ip
                ],
                ip_to_index[
                    destination_ip
                ]
            ]
        )

        edge_ports.append(
            destination_port
        )

        edge_protocols.append(
            protocol
        )

        stats = edge_statistics[
            (
                source_ip,
                destination_ip,
                destination_port,
                protocol
            )
        ]

        # -------------------------------------------------
        # Edge label
        #
        # 0 = benign only
        # 1 = attack involved
        # -------------------------------------------------

        if stats[
            "attack_count"
        ] > 0:

            edge_labels.append(
                1
            )

        else:

            edge_labels.append(
                0
            )

    edge_index = torch.tensor(
        edge_pairs,
        dtype=torch.long
    ).t().contiguous()

    edge_labels = torch.tensor(
        edge_labels,
        dtype=torch.long
    )

    edge_ports = torch.tensor(
        edge_ports,
        dtype=torch.long
    )

    edge_protocols = torch.tensor(
        edge_protocols,
        dtype=torch.long
    )

    num_edges = (
        edge_index.shape[1]
    )

    print(
        f"Unique edges: {num_edges:,}"
    )

    # =====================================================
    # STEP 4
    #
    # Reproduce deterministic train/val/test split
    # =====================================================

    print(
        "\nSTEP 4: Creating train/validation/test split..."
    )

    benign_indices = torch.where(
        edge_labels == 0
    )[0]

    attack_indices = torch.where(
        edge_labels == 1
    )[0]

    generator = torch.Generator()

    generator.manual_seed(
        RANDOM_SEED
    )

    benign_indices = benign_indices[
        torch.randperm(
            len(benign_indices),
            generator=generator
        )
    ]

    attack_indices = attack_indices[
        torch.randperm(
            len(attack_indices),
            generator=generator
        )
    ]

    def split_indices(indices):

        n = len(indices)

        train_end = int(
            n * TRAIN_RATIO
        )

        val_end = (
            train_end
            + int(
                n * VAL_RATIO
            )
        )

        return (
            indices[:train_end],
            indices[train_end:val_end],
            indices[val_end:]
        )

    (
        benign_train,
        benign_val,
        benign_test
    ) = split_indices(
        benign_indices
    )

    (
        attack_train,
        attack_val,
        attack_test
    ) = split_indices(
        attack_indices
    )

    train_indices = torch.cat(
        [
            benign_train,
            attack_train
        ]
    )

    val_indices = torch.cat(
        [
            benign_val,
            attack_val
        ]
    )

    test_indices = torch.cat(
        [
            benign_test,
            attack_test
        ]
    )

    # -----------------------------------------------------
    # Shuffle each final set
    # -----------------------------------------------------

    train_indices = train_indices[
        torch.randperm(
            len(train_indices),
            generator=generator
        )
    ]

    val_indices = val_indices[
        torch.randperm(
            len(val_indices),
            generator=generator
        )
    ]

    test_indices = test_indices[
        torch.randperm(
            len(test_indices),
            generator=generator
        )
    ]

    print(
        f"Train edges: {len(train_indices):,}"
    )

    print(
        f"Validation edges: {len(val_indices):,}"
    )

    print(
        f"Test edges: {len(test_indices):,}"
    )

    # =====================================================
    # STEP 5
    #
    # Build node statistics using TRAIN EDGES ONLY
    # =====================================================

    print(
        "\nSTEP 5: Building TRAIN-ONLY node features..."
    )

    node_statistics = {
        ip: create_node_statistics()
        for ip in sorted_ips
    }

    # -----------------------------------------------------
    # Only train edges are allowed to contribute to
    # node statistics.
    # -----------------------------------------------------

    train_edge_set = set(
        train_indices.tolist()
    )

    # -----------------------------------------------------
    # Re-read dataset because node statistics require
    # traffic features from individual flows.
    # -----------------------------------------------------

    processed_train_flows = 0

    for file_index, file in enumerate(
        files,
        start=1
    ):

        print(
            f"\n[{file_index}/{len(files)}] "
            f"Building train features from "
            f"{file.name}"
        )

        df = pd.read_csv(
            file,
            encoding="latin1",
            low_memory=False
        )

        df.columns = (
            df.columns
            .str.strip()
        )

        required_columns = [
            "Source IP",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Label"
        ] + NODE_FEATURE_COLUMNS

        missing_columns = [
            column
            for column in required_columns
            if column not in df.columns
        ]

        if missing_columns:

            raise ValueError(
                f"Missing columns in "
                f"{file.name}: "
                f"{missing_columns}"
            )

        df = df.dropna(
            subset=[
                "Source IP",
                "Destination IP",
                "Label"
            ]
        )

        # -------------------------------------------------
        # Numeric conversion
        # -------------------------------------------------

        numeric_columns = [
            "Destination Port",
            "Protocol"
        ] + NODE_FEATURE_COLUMNS

        for column in numeric_columns:

            df[column] = safe_numeric(
                df[column]
            )

        # -------------------------------------------------
        # Process rows
        # -------------------------------------------------

        for row in df[
            [
                "Source IP",
                "Destination IP",
                "Destination Port",
                "Protocol",
                "Flow Duration",
                "Total Fwd Packets",
                "Total Backward Packets",
                "Total Length of Fwd Packets",
                "Total Length of Bwd Packets",
                "Flow Bytes/s",
                "Flow Packets/s",
                "Average Packet Size"
            ]
        ].itertuples(
            index=False,
            name=None
        ):

            source_ip = str(
                row[0]
            ).strip()

            destination_ip = str(
                row[1]
            ).strip()

            destination_port = int(
                row[2]
            )

            protocol = int(
                row[3]
            )

            # -------------------------------------------------
            # Construct edge key
            # -------------------------------------------------

            edge_key = (
                source_ip,
                destination_ip,
                destination_port,
                protocol
            )

            # -------------------------------------------------
            # Find original edge index
            #
            # We create a lookup below.
            # -------------------------------------------------

            edge_index_value = edge_lookup.get(
                edge_key
            )

            if edge_index_value is None:

                continue

            # -------------------------------------------------
            # Only TRAIN edges contribute to node features
            # -------------------------------------------------

            if edge_index_value not in train_edge_set:

                continue

            # -------------------------------------------------
            # Traffic values
            # -------------------------------------------------

            duration = float(
                row[4]
            )

            fwd_packets = float(
                row[5]
            )

            bwd_packets = float(
                row[6]
            )

            fwd_bytes = float(
                row[7]
            )

            bwd_bytes = float(
                row[8]
            )

            bytes_per_second = float(
                row[9]
            )

            packets_per_second = float(
                row[10]
            )

            packet_size = float(
                row[11]
            )

            # =================================================
            # SOURCE NODE
            # =================================================

            source_stats = node_statistics[
                source_ip
            ]

            source_stats[
                "flow_count"
            ] += 1

            source_stats[
                "outbound_flows"
            ] += 1

            source_stats[
                "outbound_packets"
            ] += fwd_packets

            source_stats[
                "outbound_bytes"
            ] += fwd_bytes

            source_stats[
                "duration_sum"
            ] += duration

            source_stats[
                "bytes_per_second_sum"
            ] += bytes_per_second

            source_stats[
                "packets_per_second_sum"
            ] += packets_per_second

            source_stats[
                "packet_size_sum"
            ] += packet_size

            source_stats[
                "peers"
            ].add(
                destination_ip
            )

            # =================================================
            # DESTINATION NODE
            # =================================================

            destination_stats = node_statistics[
                destination_ip
            ]

            destination_stats[
                "flow_count"
            ] += 1

            destination_stats[
                "inbound_flows"
            ] += 1

            destination_stats[
                "inbound_packets"
            ] += bwd_packets

            destination_stats[
                "inbound_bytes"
            ] += bwd_bytes

            destination_stats[
                "duration_sum"
            ] += duration

            destination_stats[
                "bytes_per_second_sum"
            ] += bytes_per_second

            destination_stats[
                "packets_per_second_sum"
            ] += packets_per_second

            destination_stats[
                "packet_size_sum"
            ] += packet_size

            destination_stats[
                "peers"
            ].add(
                source_ip
            )

            # =================================================
            # PROTOCOL
            # =================================================

            if protocol == 6:

                source_stats[
                    "tcp_flows"
                ] += 1

                destination_stats[
                    "tcp_flows"
                ] += 1

            elif protocol == 17:

                source_stats[
                    "udp_flows"
                ] += 1

                destination_stats[
                    "udp_flows"
                ] += 1

            processed_train_flows += 1

        del df

    print(
        f"\nTRAIN flows contributing to "
        f"node features: "
        f"{processed_train_flows:,}"
    )

    # =====================================================
    # STEP 6
    #
    # Build node feature matrix
    # =====================================================

    print(
        "\nSTEP 6: Creating node feature matrix..."
    )

    node_features = []

    for ip in sorted_ips:

        stats = node_statistics[
            ip
        ]

        flows = max(
            stats["flow_count"],
            1
        )

        features = [

            stats[
                "flow_count"
            ],

            stats[
                "outbound_flows"
            ],

            stats[
                "inbound_flows"
            ],

            stats[
                "outbound_packets"
            ],

            stats[
                "inbound_packets"
            ],

            stats[
                "outbound_bytes"
            ],

            stats[
                "inbound_bytes"
            ],

            stats[
                "duration_sum"
            ] / flows,

            stats[
                "bytes_per_second_sum"
            ] / flows,

            stats[
                "packets_per_second_sum"
            ] / flows,

            stats[
                "packet_size_sum"
            ] / flows,

            stats[
                "tcp_flows"
            ],

            stats[
                "udp_flows"
            ],

            len(
                stats["peers"]
            )
        ]

        node_features.append(
            features
        )

    x = torch.tensor(
        node_features,
        dtype=torch.float32
    )

    # -----------------------------------------------------
    # Final safety check
    # -----------------------------------------------------

    if not torch.isfinite(
        x
    ).all():

        raise ValueError(
            "Node features contain "
            "NaN or infinite values."
        )

    print(
        f"Node feature matrix: "
        f"{x.shape}"
    )

    # =====================================================
    # STEP 7
    #
    # Save leakage-safe graph
    # =====================================================

    graph_data = {

        "x": x,

        "edge_index": edge_index,

        "edge_labels": edge_labels,

        "edge_ports": edge_ports,

        "edge_protocols": edge_protocols,

        "index_to_ip": index_to_ip,

        "num_nodes": num_nodes,

        "num_edges": num_edges,

        "total_flows": total_flows,

        "train_indices": train_indices,

        "val_indices": val_indices,

        "test_indices": test_indices,

        "feature_names": [

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
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    torch.save(
        graph_data,
        OUTPUT_FILE
    )

    # =====================================================
    # SUMMARY
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "LEAKAGE-SAFE GRAPH CREATED"
    )

    print(
        "=" * 70
    )

    print(
        f"\nNodes: "
        f"{num_nodes:,}"
    )

    print(
        f"Edges: "
        f"{num_edges:,}"
    )

    print(
        f"Total flows: "
        f"{total_flows:,}"
    )

    print(
        f"Train edges: "
        f"{len(train_indices):,}"
    )

    print(
        f"Validation edges: "
        f"{len(val_indices):,}"
    )

    print(
        f"Test edges: "
        f"{len(test_indices):,}"
    )

    print(
        f"Node features: "
        f"{x.shape[1]}"
    )

    print(
        f"\nBenign edges: "
        f"{(edge_labels == 0).sum().item():,}"
    )

    print(
        f"Attack edges: "
        f"{(edge_labels == 1).sum().item():,}"
    )

    print(
        "\nSaved to:"
    )

    print(
        OUTPUT_FILE
    )

    print(
        "=" * 70
    )


# =========================================================
# EDGE LOOKUP
#
# This is created before build_graph() runs.
# =========================================================

edge_lookup = {}


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    # -----------------------------------------------------
    # We need to create the edge lookup before processing
    # train-only node features.
    #
    # Build the lookup from the raw dataset first.
    # -----------------------------------------------------

    print(
        "Preparing edge lookup..."
    )

    files = sorted(
        DATASET_DIR.rglob("*.csv")
    )

    temp_edges = set()

    for file in files:

        df = pd.read_csv(
            file,
            encoding="latin1",
            low_memory=False
        )

        df.columns = (
            df.columns
            .str.strip()
        )

        df = df.dropna(
            subset=[
                "Source IP",
                "Destination IP",
                "Label"
            ]
        )

        df["Destination Port"] = safe_numeric(
            df["Destination Port"]
        )

        df["Protocol"] = safe_numeric(
            df["Protocol"]
        )

        for row in df[
            [
                "Source IP",
                "Destination IP",
                "Destination Port",
                "Protocol"
            ]
        ].itertuples(
            index=False,
            name=None
        ):

            source_ip = str(
                row[0]
            ).strip()

            destination_ip = str(
                row[1]
            ).strip()

            destination_port = int(
                row[2]
            )

            protocol = int(
                row[3]
            )

            edge_key = (
                source_ip,
                destination_ip,
                destination_port,
                protocol
            )

            temp_edges.add(
                edge_key
            )

        del df

    # -----------------------------------------------------
    # IMPORTANT:
    #
    # sorted() gives exactly the same deterministic
    # ordering used inside build_graph().
    # -----------------------------------------------------

    for index, edge_key in enumerate(
        sorted(temp_edges)
    ):

        edge_lookup[
            edge_key
        ] = index

    print(
        f"Edge lookup created: "
        f"{len(edge_lookup):,}"
    )

    build_graph()
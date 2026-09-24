import pandas as pd
from pathlib import Path


# ============================================================
# OUTPUT FILE
# ============================================================

OUTPUT_FILE = Path(
    "data/normal_traffic.csv"
)


# ============================================================
# COLUMN ORDER
# ============================================================

COLUMNS = [
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration",
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "unique_destination_ips",
    "unique_destination_ports",
    "tcp_syn_count",
    "tcp_rst_count"
]


# ============================================================
# SAVE FEATURES
# ============================================================

def save_features(features):

    # Nothing to save
    if not features:

        return

    # Convert features into DataFrame
    df = pd.DataFrame(features)

    # Make sure all expected columns exist
    missing_columns = [
        column
        for column in COLUMNS
        if column not in df.columns
    ]

    if missing_columns:

        raise ValueError(
            f"Missing columns: {missing_columns}"
        )

    # Keep columns in a fixed order
    df = df[COLUMNS]

    # Create data directory
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # First write
    # --------------------------------------------------------

    if not OUTPUT_FILE.exists():

        df.to_csv(
            OUTPUT_FILE,
            index=False
        )

    # --------------------------------------------------------
    # Append to existing dataset
    # --------------------------------------------------------

    else:

        df.to_csv(
            OUTPUT_FILE,
            mode="a",
            header=False,
            index=False
        )

    print(
        f"Saved {len(df)} flows to "
        f"{OUTPUT_FILE}"
    )
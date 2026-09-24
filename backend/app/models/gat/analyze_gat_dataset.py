import pandas as pd
from pathlib import Path


DATASET_DIR = Path("data/gat/generated_flows")


def main():

    files = list(DATASET_DIR.rglob("*.csv"))

    print("=" * 70)
    print("CIC-IDS2017 GAT DATASET ANALYSIS")
    print("=" * 70)

    print(f"\nCSV files found: {len(files)}")

    total_rows = 0
    label_counts = {}
    source_ips = set()
    destination_ips = set()

    missing_source = 0
    missing_destination = 0
    missing_label = 0

    print("\nFiles:")
    for file in files:
        print(f"  - {file.name}")

    print("\nAnalyzing files...\n")

    for index, file in enumerate(files, start=1):

        print(f"[{index}/{len(files)}] Reading {file.name}")

        df = pd.read_csv(
        file,
         encoding="latin1"
        )

        df.columns = df.columns.str.strip()

        # Remove completely invalid flow records.
        # These rows do not contain the information needed
        # to construct a communication graph.
        df = df.dropna(
        subset=[
        "Source IP",
        "Destination IP",
        "Label"
        ]
        )

        rows = len(df)
        total_rows += rows

        # Label statistics
        counts = df["Label"].value_counts()

        for label, count in counts.items():
            label_counts[label] = (
                label_counts.get(label, 0) + int(count)
            )

        # IP statistics
        source_ips.update(
            df["Source IP"].dropna().astype(str)
        )

        destination_ips.update(
            df["Destination IP"].dropna().astype(str)
        )

        # Missing values
        missing_source += int(
            df["Source IP"].isna().sum()
        )

        missing_destination += int(
            df["Destination IP"].isna().sum()
        )

        missing_label += int(
            df["Label"].isna().sum()
        )

        print(f"    Rows: {rows:,}")

    print("\n" + "=" * 70)
    print("COMBINED DATASET STATISTICS")
    print("=" * 70)

    print(f"\nTotal flows: {total_rows:,}")

    print("\nLabel counts:")

    for label, count in sorted(
        label_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        print(f"  {label}: {count:,}")

    print(
        f"\nUnique source IPs: "
        f"{len(source_ips):,}"
    )

    print(
        f"Unique destination IPs: "
        f"{len(destination_ips):,}"
    )

    all_ips = source_ips | destination_ips

    print(
        f"Unique IPs overall: "
        f"{len(all_ips):,}"
    )

    print("\nMissing values:")

    print(
        f"  Source IP: "
        f"{missing_source:,}"
    )

    print(
        f"  Destination IP: "
        f"{missing_destination:,}"
    )

    print(
        f"  Label: "
        f"{missing_label:,}"
    )

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
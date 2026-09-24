import pandas as pd
from pathlib import Path


DATASET_DIR = Path("data/gat/generated_flows")


def main():

    files = list(DATASET_DIR.rglob("*.csv"))

    print("=" * 70)
    print("CHECKING MISSING VALUES PER FILE")
    print("=" * 70)

    for file in files:

        print(f"\nReading: {file.name}")

        df = pd.read_csv(
            file,
            encoding="latin1"
        )

        df.columns = df.columns.str.strip()

        missing_source = df["Source IP"].isna().sum()
        missing_destination = df["Destination IP"].isna().sum()
        missing_label = df["Label"].isna().sum()

        print(f"Rows: {len(df):,}")
        print(f"Missing Source IP: {missing_source:,}")
        print(
            f"Missing Destination IP: "
            f"{missing_destination:,}"
        )
        print(f"Missing Label: {missing_label:,}")


if __name__ == "__main__":
    main()
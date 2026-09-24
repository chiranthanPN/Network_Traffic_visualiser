import pandas as pd
from pathlib import Path


FILE = next(
    Path("data/gat/generated_flows").rglob(
        "Thursday-WorkingHours-Morning-WebAttacks*.csv"
    )
)


def main():

    print("=" * 70)
    print("INSPECTING WEB ATTACKS DATASET")
    print("=" * 70)

    print(f"\nFile: {FILE}")

    df = pd.read_csv(
        FILE,
        encoding="latin1",
        low_memory=False
    )

    df.columns = df.columns.str.strip()

    print(f"\nRows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    missing = df["Source IP"].isna()

    print(
        f"\nRows missing Source IP: "
        f"{missing.sum():,}"
    )

    print("\nFirst 5 problematic rows:")

    print(
        df.loc[
            missing,
            [
                "Flow ID",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Destination Port",
                "Protocol",
                "Timestamp",
                "Label"
            ]
        ].head(5).to_string()
    )

    print("\nFirst 5 valid rows:")

    print(
        df.loc[
            ~missing,
            [
                "Flow ID",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Destination Port",
                "Protocol",
                "Timestamp",
                "Label"
            ]
        ].head(5).to_string()
    )


if __name__ == "__main__":
    main()
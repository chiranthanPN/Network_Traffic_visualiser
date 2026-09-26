from pathlib import Path

from .isolation_forest import train_model


# Dataset location
DATASET = Path(
    "data/normal_traffic.csv"
)


def main():

    if not DATASET.exists():

        raise FileNotFoundError(
            f"Dataset not found: {DATASET}"
        )

    train_model(
        DATASET
    )


if __name__ == "__main__":

    main()
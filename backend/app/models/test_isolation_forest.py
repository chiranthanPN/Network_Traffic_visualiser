import pandas as pd

from isolation_forest import load_model, predict


DATASET = "data/normal_traffic.csv"


def main():

    print("Loading trained model...")

    model = load_model()

    print("Model loaded successfully.")

    # Load a few records
    data = pd.read_csv(
        DATASET
    ).head(10)

    results = predict(
        model,
        data
    )

    print("\nIsolation Forest Results")
    print("=" * 50)

    for index, result in enumerate(
        results,
        start=1
    ):

        print(
            f"Flow {index}"
        )

        print(
            f"Anomaly: "
            f"{result['is_anomaly']}"
        )

        print(
            f"Score: "
            f"{result['anomaly_score']:.6f}"
        )

        print("-" * 50)


if __name__ == "__main__":

    main()
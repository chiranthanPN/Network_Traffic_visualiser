from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


# ============================================================
# FEATURES USED BY ISOLATION FOREST
# ============================================================

FEATURES = [
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
# MODEL LOCATION
# ============================================================

MODEL_PATH = Path(
    "trained_models/isolation_forest.pkl"
)


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model(csv_path):

    print("\nLoading training dataset...")

    data = pd.read_csv(csv_path)

    print(
        f"Total flow records: {len(data)}"
    )

    # --------------------------------------------------------
    # Check required columns
    # --------------------------------------------------------

    missing_features = [
        feature
        for feature in FEATURES
        if feature not in data.columns
    ]

    if missing_features:

        raise ValueError(
            f"Missing features: {missing_features}"
        )

    # --------------------------------------------------------
    # Select only ML features
    # --------------------------------------------------------

    X = data[FEATURES].copy()

    # --------------------------------------------------------
    # Convert values to numeric
    # --------------------------------------------------------

    for feature in FEATURES:

        X[feature] = pd.to_numeric(
            X[feature],
            errors="coerce"
        )

    # --------------------------------------------------------
    # Remove invalid rows
    # --------------------------------------------------------

    before = len(X)

    X = X.dropna()

    after = len(X)

    print(
        f"Valid training records: {after}"
    )

    print(
        f"Removed invalid records: {before - after}"
    )

    if len(X) < 50:

        raise ValueError(
            "Not enough valid training records."
        )

    # --------------------------------------------------------
    # Create Isolation Forest
    # --------------------------------------------------------

    print("\nTraining Isolation Forest...")

    model = IsolationForest(

        n_estimators=200,

        contamination="auto",

        random_state=42,

        n_jobs=-1
    )

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    model.fit(X)

    # --------------------------------------------------------
    # Create model directory
    # --------------------------------------------------------

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Save model
    # --------------------------------------------------------

    joblib.dump(
        model,
        MODEL_PATH
    )

    print(
        f"\nModel saved successfully:"
    )

    print(
        MODEL_PATH
    )

    return model


# ============================================================
# LOAD MODEL
# ============================================================

def load_model():

    if not MODEL_PATH.exists():

        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    return joblib.load(
        MODEL_PATH
    )


# ============================================================
# PREDICT
# ============================================================

def predict(model, data):

    X = data[FEATURES].copy()

    for feature in FEATURES:

        X[feature] = pd.to_numeric(
            X[feature],
            errors="coerce"
        )

    X = X.fillna(0)

    # Isolation Forest prediction:
    #
    #  1  = normal
    # -1  = anomaly

    predictions = model.predict(X)

    # Higher values generally indicate
    # observations closer to the learned normal region.
    scores = model.decision_function(X)

    results = []

    for prediction, score in zip(
        predictions,
        scores
    ):

        results.append({

            "is_anomaly":
                prediction == -1,

            "anomaly_score":
                float(score)
        })

    return results
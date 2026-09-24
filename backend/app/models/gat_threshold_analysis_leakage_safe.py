import json
from pathlib import Path

import numpy as np
import torch

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

from app.models.gat_model import GATNetwork


# =========================================================
# PATHS
# =========================================================

GRAPH_PATH = Path(
    "data/gat/gat_graph_leakage_safe.pt"
)

MODEL_PATH = Path(
    "trained_models/gat/gat_model_leakage_safe.pt"
)

THRESHOLD_PATH = Path(
    "trained_models/gat/gat_threshold.json"
)


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 70)
    print("LEAKAGE-SAFE GAT THRESHOLD ANALYSIS")
    print("=" * 70)

    # =====================================================
    # DEVICE
    # =====================================================

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    print(
        f"\nDevice: {device}"
    )

    if device.type == "cuda":

        print(
            f"GPU: "
            f"{torch.cuda.get_device_name(0)}"
        )

    # =====================================================
    # LOAD GRAPH
    # =====================================================

    print(
        "\nLoading leakage-safe graph..."
    )

    graph = torch.load(
        GRAPH_PATH,
        weights_only=False
    )

    x = graph["x"]

    edge_index = graph["edge_index"]

    labels = graph["edge_labels"]

    train_indices = graph["train_indices"]

    val_indices = graph["val_indices"]

    test_indices = graph["test_indices"]

    print(
        f"Nodes: {graph['num_nodes']:,}"
    )

    print(
        f"Edges: {graph['num_edges']:,}"
    )

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
    # LOAD MODEL CHECKPOINT
    # =====================================================

    print(
        "\nLoading leakage-safe GAT model..."
    )

    checkpoint = torch.load(
        MODEL_PATH,
        map_location=device,
        weights_only=False
    )

    # =====================================================
    # LOAD TRAIN-ONLY NORMALIZATION PARAMETERS
    # =====================================================

    feature_mean = checkpoint[
        "feature_mean"
    ]

    feature_std = checkpoint[
        "feature_std"
    ]

    # =====================================================
    # MOVE FEATURES AND NORMALIZATION PARAMETERS
    # TO THE SAME DEVICE
    # =====================================================

    # IMPORTANT:
    #
    # x, feature_mean and feature_std must all be on
    # the same device before performing:
    #
    # (x - feature_mean) / feature_std
    #
    # The previous version performed this operation while
    # x was on CPU and later moved x to CUDA.
    # =====================================================

    x = x.to(
        device
    )

    feature_mean = feature_mean.to(
        device
    )

    feature_std = feature_std.to(
        device
    )

    # =====================================================
    # NORMALIZE USING TRAIN-ONLY STATISTICS
    # =====================================================

    print(
        "\nNormalizing node features..."
    )

    x = (
        x - feature_mean
    ) / feature_std

    # =====================================================
    # SAFETY CHECK
    # =====================================================

    if not torch.isfinite(
        x
    ).all():

        raise RuntimeError(
            "Normalized features contain NaN "
            "or infinite values."
        )

    print(
        "Feature normalization successful."
    )

    # =====================================================
    # MOVE OTHER DATA TO DEVICE
    # =====================================================

    edge_index = edge_index.to(
        device
    )

    labels = labels.to(
        device
    )

    train_indices = train_indices.to(
        device
    )

    val_indices = val_indices.to(
        device
    )

    test_indices = test_indices.to(
        device
    )

    # =====================================================
    # RECREATE MODEL
    # =====================================================

    model = GATNetwork(
        input_dim=checkpoint[
            "input_dim"
        ],

        hidden_dim=checkpoint[
            "hidden_dim"
        ],

        heads=checkpoint[
            "heads"
        ],

        dropout=checkpoint[
            "dropout"
        ]
    ).to(
        device
    )

    # =====================================================
    # LOAD TRAINED WEIGHTS
    # =====================================================

    model.load_state_dict(
        checkpoint[
            "model_state_dict"
        ]
    )

    model.eval()

    print(
        "Model loaded successfully."
    )

    # =====================================================
    # TRAINING GRAPH ONLY
    # =====================================================

    # IMPORTANT:
    #
    # Only training edges are used for GAT message
    # passing.
    #
    # Validation and test edges are NOT used to generate
    # node embeddings.
    # =====================================================

    train_message_passing_edges = (
        edge_index[
            :,
            train_indices
        ]
    )

    # =====================================================
    # GENERATE NODE EMBEDDINGS
    # =====================================================

    print(
        "\nGenerating node embeddings..."
    )

    with torch.no_grad():

        _, embeddings = model(
            x,
            train_message_passing_edges,
            train_message_passing_edges
        )

    print(
        "Node embeddings generated."
    )

    # =====================================================
    # GET ATTACK PROBABILITIES
    # =====================================================

    def get_attack_probabilities(
        indices
    ):

        with torch.no_grad():

            # ---------------------------------------------
            # Source nodes
            # ---------------------------------------------

            source_nodes = edge_index[
                0,
                indices
            ]

            # ---------------------------------------------
            # Destination nodes
            # ---------------------------------------------

            destination_nodes = edge_index[
                1,
                indices
            ]

            # ---------------------------------------------
            # Source embeddings
            # ---------------------------------------------

            source_embeddings = embeddings[
                source_nodes
            ]

            # ---------------------------------------------
            # Destination embeddings
            # ---------------------------------------------

            destination_embeddings = embeddings[
                destination_nodes
            ]

            # ---------------------------------------------
            # Combine source + destination embeddings
            # ---------------------------------------------

            edge_embeddings = torch.cat(
                [
                    source_embeddings,
                    destination_embeddings
                ],
                dim=1
            )

            # ---------------------------------------------
            # Edge classifier
            # ---------------------------------------------

            logits = model.edge_classifier(
                edge_embeddings
            )

            # ---------------------------------------------
            # Convert logits to probabilities
            #
            # Column 0 = benign
            # Column 1 = attack
            # ---------------------------------------------

            probabilities = torch.softmax(
                logits,
                dim=1
            )[:, 1]

        return probabilities

    # =====================================================
    # VALIDATION PROBABILITIES
    # =====================================================

    print(
        "\nCalculating validation probabilities..."
    )

    val_probabilities = (
        get_attack_probabilities(
            val_indices
        )
    )

    # -----------------------------------------------------
    # Validation labels
    # -----------------------------------------------------

    val_true = (
        labels[
            val_indices
        ]
        .detach()
        .cpu()
        .numpy()
    )

    # -----------------------------------------------------
    # Validation probabilities
    # -----------------------------------------------------

    val_probabilities = (
        val_probabilities
        .detach()
        .cpu()
        .numpy()
    )

    # =====================================================
    # THRESHOLD ANALYSIS
    # =====================================================

    thresholds = np.arange(
        0.05,
        1.00,
        0.05
    )

    results = []

    print(
        "\n" + "=" * 70
    )

    print(
        "VALIDATION THRESHOLD ANALYSIS"
    )

    print(
        "=" * 70
    )

    print(
        "\nThreshold | Precision | Recall | F1"
    )

    print(
        "-" * 50
    )

    # =====================================================
    # TEST DIFFERENT THRESHOLDS
    # =====================================================

    for threshold in thresholds:

        predictions = (
            val_probabilities
            >= threshold
        ).astype(
            int
        )

        # -------------------------------------------------
        # Precision
        # -------------------------------------------------

        precision = precision_score(
            val_true,
            predictions,
            zero_division=0
        )

        # -------------------------------------------------
        # Recall
        # -------------------------------------------------

        recall = recall_score(
            val_true,
            predictions,
            zero_division=0
        )

        # -------------------------------------------------
        # F1
        # -------------------------------------------------

        f1 = f1_score(
            val_true,
            predictions,
            zero_division=0
        )

        # -------------------------------------------------
        # Store results
        # -------------------------------------------------

        results.append(
            (
                float(threshold),
                float(precision),
                float(recall),
                float(f1)
            )
        )

        # -------------------------------------------------
        # Display
        # -------------------------------------------------

        print(
            f"   {threshold:.2f}    | "
            f"  {precision:.4f}  | "
            f" {recall:.4f} | "
            f"{f1:.4f}"
        )

    # =====================================================
    # SELECT BEST F1 THRESHOLD
    # =====================================================

    (
        best_threshold,
        best_precision,
        best_recall,
        best_f1
    ) = max(
        results,
        key=lambda item: item[3]
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "SELECTED VALIDATION THRESHOLD"
    )

    print(
        "=" * 70
    )

    print(
        f"\nThreshold: "
        f"{best_threshold:.2f}"
    )

    print(
        f"Validation Precision: "
        f"{best_precision:.4f}"
    )

    print(
        f"Validation Recall: "
        f"{best_recall:.4f}"
    )

    print(
        f"Validation F1: "
        f"{best_f1:.4f}"
    )

    # =====================================================
    # TEST PROBABILITIES
    # =====================================================

    print(
        "\nCalculating test probabilities..."
    )

    test_probabilities = (
        get_attack_probabilities(
            test_indices
        )
    )

    # -----------------------------------------------------
    # Test labels
    # -----------------------------------------------------

    test_true = (
        labels[
            test_indices
        ]
        .detach()
        .cpu()
        .numpy()
    )

    # -----------------------------------------------------
    # Test probabilities
    # -----------------------------------------------------

    test_probabilities = (
        test_probabilities
        .detach()
        .cpu()
        .numpy()
    )

    # =====================================================
    # APPLY SELECTED THRESHOLD
    # =====================================================

    test_predictions = (
        test_probabilities
        >= best_threshold
    ).astype(
        int
    )

    # =====================================================
    # TEST METRICS
    # =====================================================

    test_precision = precision_score(
        test_true,
        test_predictions,
        zero_division=0
    )

    test_recall = recall_score(
        test_true,
        test_predictions,
        zero_division=0
    )

    test_f1 = f1_score(
        test_true,
        test_predictions,
        zero_division=0
    )

    test_confusion = confusion_matrix(
        test_true,
        test_predictions
    )

    # =====================================================
    # DISPLAY TEST RESULTS
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "FINAL TEST RESULTS"
    )

    print(
        "=" * 70
    )

    print(
        f"\nThreshold: "
        f"{best_threshold:.2f}"
    )

    print(
        f"Precision: "
        f"{test_precision:.4f}"
    )

    print(
        f"Recall:    "
        f"{test_recall:.4f}"
    )

    print(
        f"F1 Score:  "
        f"{test_f1:.4f}"
    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        test_confusion
    )

    # =====================================================
    # DETAILED COUNTS
    # =====================================================

    if test_confusion.shape == (2, 2):

        tn = test_confusion[0][0]

        fp = test_confusion[0][1]

        fn = test_confusion[1][0]

        tp = test_confusion[1][1]

        print(
            "\nDetailed counts:"
        )

        print(
            f"True Negatives:  {tn:,}"
        )

        print(
            f"False Positives: {fp:,}"
        )

        print(
            f"False Negatives: {fn:,}"
        )

        print(
            f"True Positives:  {tp:,}"
        )

    # =====================================================
    # SAVE SELECTED THRESHOLD
    # =====================================================

    THRESHOLD_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    threshold_data = {

        "threshold":
            best_threshold,

        "validation_precision":
            best_precision,

        "validation_recall":
            best_recall,

        "validation_f1":
            best_f1,

        "test_precision":
            float(test_precision),

        "test_recall":
            float(test_recall),

        "test_f1":
            float(test_f1),

        "model":
            str(MODEL_PATH),

        "graph":
            str(GRAPH_PATH),

        "evaluation_type":
            "leakage_safe",

        "message_passing":
            "training_edges_only"
    }

    with open(
        THRESHOLD_PATH,
        "w"
    ) as file:

        json.dump(
            threshold_data,
            file,
            indent=4
        )

    print(
        "\nSelected threshold saved to:"
    )

    print(
        THRESHOLD_PATH
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "LEAKAGE-SAFE THRESHOLD ANALYSIS COMPLETE"
    )

    print(
        "=" * 70
    )


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    main()
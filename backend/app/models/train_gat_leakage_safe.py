import random
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn

from sklearn.metrics import (
    accuracy_score,
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


# =========================================================
# SETTINGS
# =========================================================

RANDOM_SEED = 42

HIDDEN_DIM = 32
HEADS = 4
DROPOUT = 0.30

LEARNING_RATE = 0.001
WEIGHT_DECAY = 0.0001

EPOCHS = 30
PATIENCE = 5


# =========================================================
# RANDOM SEED
# =========================================================

def set_seed(seed=42):

    random.seed(seed)

    np.random.seed(seed)

    torch.manual_seed(seed)

    if torch.cuda.is_available():

        torch.cuda.manual_seed_all(seed)


# =========================================================
# LOAD GRAPH
# =========================================================

def load_graph():

    print("\nLoading leakage-safe graph...")

    graph = torch.load(
        GRAPH_PATH,
        weights_only=False
    )

    print(
        f"Nodes: {graph['num_nodes']:,}"
    )

    print(
        f"Edges: {graph['num_edges']:,}"
    )

    print(
        f"Node features: "
        f"{graph['x'].shape[1]}"
    )

    return graph


# =========================================================
# NORMALIZE NODE FEATURES
#
# IMPORTANT:
# Calculate normalization statistics only from nodes
# participating in TRAIN edges.
# =========================================================

def normalize_features(
    x,
    train_edge_index,
    num_nodes
):

    print(
        "\nNormalizing node features using TRAIN nodes only..."
    )

    # -----------------------------------------------------
    # Nodes appearing in training graph
    # -----------------------------------------------------

    train_nodes = torch.unique(
        train_edge_index.reshape(-1)
    )

    print(
        f"Training graph nodes: "
        f"{len(train_nodes):,}"
    )

    # -----------------------------------------------------
    # Calculate statistics only from training nodes
    # -----------------------------------------------------

    train_x = x[
        train_nodes
    ]

    mean = train_x.mean(
        dim=0,
        keepdim=True
    )

    std = train_x.std(
        dim=0,
        keepdim=True
    )

    # -----------------------------------------------------
    # Prevent division by zero
    # -----------------------------------------------------

    std = torch.where(
        std < 1e-8,
        torch.ones_like(std),
        std
    )

    # -----------------------------------------------------
    # Normalize all nodes using TRAIN statistics
    #
    # No test information is used to calculate mean/std.
    # -----------------------------------------------------

    x_normalized = (
        x - mean
    ) / std

    # -----------------------------------------------------
    # Safety check
    # -----------------------------------------------------

    if not torch.isfinite(
        x_normalized
    ).all():

        raise ValueError(
            "Normalized node features contain "
            "NaN or infinite values."
        )

    return (
        x_normalized,
        mean,
        std
    )


# =========================================================
# CLASS WEIGHTS
# =========================================================

def calculate_class_weights(
    labels,
    train_indices
):

    train_labels = labels[
        train_indices
    ]

    benign_count = (
        train_labels == 0
    ).sum().item()

    attack_count = (
        train_labels == 1
    ).sum().item()

    print(
        "\nTraining class distribution:"
    )

    print(
        f"  Benign: {benign_count:,}"
    )

    print(
        f"  Attack: {attack_count:,}"
    )

    if attack_count == 0:

        raise ValueError(
            "Training set contains no attack edges."
        )

    # -----------------------------------------------------
    # Balanced class weights
    # -----------------------------------------------------

    total = (
        benign_count +
        attack_count
    )

    benign_weight = (
        total /
        (2.0 * benign_count)
    )

    attack_weight = (
        total /
        (2.0 * attack_count)
    )

    weights = torch.tensor(
        [
            benign_weight,
            attack_weight
        ],
        dtype=torch.float32
    )

    print(
        "\nClass weights:"
    )

    print(
        f"  Benign: {benign_weight:.4f}"
    )

    print(
        f"  Attack: {attack_weight:.4f}"
    )

    return weights


# =========================================================
# EDGE CLASSIFICATION
# =========================================================

def classify_edges(
    model,
    embeddings,
    edge_index,
    indices
):

    source_nodes = edge_index[
        0,
        indices
    ]

    destination_nodes = edge_index[
        1,
        indices
    ]

    source_embeddings = embeddings[
        source_nodes
    ]

    destination_embeddings = embeddings[
        destination_nodes
    ]

    edge_embeddings = torch.cat(
        [
            source_embeddings,
            destination_embeddings
        ],
        dim=1
    )

    logits = model.edge_classifier(
        edge_embeddings
    )

    return logits


# =========================================================
# CALCULATE METRICS
# =========================================================

def calculate_metrics(
    labels,
    predictions
):

    y_true = labels.detach().cpu().numpy()

    y_pred = predictions.detach().cpu().numpy()

    return {
        "accuracy": accuracy_score(
            y_true,
            y_pred
        ),

        "precision": precision_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "recall": recall_score(
            y_true,
            y_pred,
            zero_division=0
        ),

        "f1": f1_score(
            y_true,
            y_pred,
            zero_division=0
        )
    }


# =========================================================
# MAIN TRAINING
# =========================================================

def train():

    set_seed(
        RANDOM_SEED
    )

    print(
        "=" * 70
    )

    print(
        "LEAKAGE-SAFE GAT TRAINING"
    )

    print(
        "=" * 70
    )

    # =====================================================
    # DEVICE
    # =====================================================

    if torch.cuda.is_available():

        device = torch.device(
            "cuda"
        )

        print(
            f"\nUsing GPU: "
            f"{torch.cuda.get_device_name(0)}"
        )

    else:

        device = torch.device(
            "cpu"
        )

        print(
            "\nCUDA not available."
        )

        print(
            "Using CPU."
        )

    # =====================================================
    # LOAD GRAPH
    # =====================================================

    graph = load_graph()

    x = graph[
        "x"
    ]

    edge_index = graph[
        "edge_index"
    ]

    labels = graph[
        "edge_labels"
    ]

    train_indices = graph[
        "train_indices"
    ]

    val_indices = graph[
        "val_indices"
    ]

    test_indices = graph[
        "test_indices"
    ]

    # =====================================================
    # BUILD TRAINING GRAPH
    # =====================================================

    train_message_passing_edges = edge_index[
        :,
        train_indices
    ]

    # =====================================================
    # NORMALIZE FEATURES
    # =====================================================

    (
        x,
        feature_mean,
        feature_std
    ) = normalize_features(
        x,
        train_message_passing_edges,
        graph["num_nodes"]
    )

    # =====================================================
    # DISPLAY SPLIT
    # =====================================================

    print(
        "\nDataset split:"
    )

    print(
        f"  Train edges: "
        f"{len(train_indices):,}"
    )

    print(
        f"  Validation edges: "
        f"{len(val_indices):,}"
    )

    print(
        f"  Test edges: "
        f"{len(test_indices):,}"
    )

    # =====================================================
    # MOVE TO DEVICE
    # =====================================================

    x = x.to(
        device
    )

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

    train_message_passing_edges = (
        train_message_passing_edges.to(
            device
        )
    )

    # =====================================================
    # CLASS WEIGHTS
    # =====================================================

    class_weights = calculate_class_weights(
        labels,
        train_indices
    )

    class_weights = class_weights.to(
        device
    )

    # =====================================================
    # MODEL
    # =====================================================

    input_dim = x.shape[
        1
    ]

    model = GATNetwork(
        input_dim=input_dim,
        hidden_dim=HIDDEN_DIM,
        heads=HEADS,
        dropout=DROPOUT
    ).to(
        device
    )

    print(
        "\nModel:"
    )

    print(
        model
    )

    # =====================================================
    # LOSS
    # =====================================================

    criterion = nn.CrossEntropyLoss(
        weight=class_weights
    )

    # =====================================================
    # OPTIMIZER
    # =====================================================

    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LEARNING_RATE,
        weight_decay=WEIGHT_DECAY
    )

    # =====================================================
    # TRAINING VARIABLES
    # =====================================================

    best_val_f1 = -1.0

    patience_counter = 0

    best_state = None

    # =====================================================
    # TRAINING LOOP
    # =====================================================

    print(
        "\nStarting training..."
    )

    print(
        "=" * 70
    )

    for epoch in range(
        1,
        EPOCHS + 1
    ):

        # -------------------------------------------------
        # TRAIN
        # -------------------------------------------------

        model.train()

        optimizer.zero_grad()

        # -------------------------------------------------
        # Generate node embeddings using TRAIN graph only
        # -------------------------------------------------

        _, embeddings = model(
            x,
            train_message_passing_edges,
            train_message_passing_edges
        )

        # -------------------------------------------------
        # Classify training edges
        # -------------------------------------------------

        train_logits = classify_edges(
            model,
            embeddings,
            edge_index,
            train_indices
        )

        train_labels = labels[
            train_indices
        ]

        # -------------------------------------------------
        # Loss
        # -------------------------------------------------

        loss = criterion(
            train_logits,
            train_labels
        )

        # -------------------------------------------------
        # Safety check
        # -------------------------------------------------

        if not torch.isfinite(
            loss
        ):

            raise RuntimeError(
                f"Non-finite loss at epoch "
                f"{epoch}: {loss.item()}"
            )

        # -------------------------------------------------
        # Backpropagation
        # -------------------------------------------------

        loss.backward()

        optimizer.step()

        # -------------------------------------------------
        # VALIDATION
        # -------------------------------------------------

        model.eval()

        with torch.no_grad():

            # ---------------------------------------------
            # Recalculate embeddings from TRAIN graph only
            # ---------------------------------------------

            _, embeddings = model(
                x,
                train_message_passing_edges,
                train_message_passing_edges
            )

            val_logits = classify_edges(
                model,
                embeddings,
                edge_index,
                val_indices
            )

            val_predictions = torch.argmax(
                val_logits,
                dim=1
            )

            val_labels = labels[
                val_indices
            ]

        metrics = calculate_metrics(
            val_labels,
            val_predictions
        )

        print(
            f"Epoch {epoch:02d} | "
            f"Loss: {loss.item():.4f} | "
            f"Val Precision: "
            f"{metrics['precision']:.4f} | "
            f"Val Recall: "
            f"{metrics['recall']:.4f} | "
            f"Val F1: "
            f"{metrics['f1']:.4f}"
        )

        # =================================================
        # SAVE BEST MODEL
        # =================================================

        if metrics["f1"] > best_val_f1:

            best_val_f1 = metrics[
                "f1"
            ]

            patience_counter = 0

            best_state = {
                key: value.detach().cpu().clone()
                for key, value
                in model.state_dict().items()
            }

        else:

            patience_counter += 1

        # -------------------------------------------------
        # Early stopping
        # -------------------------------------------------

        if patience_counter >= PATIENCE:

            print(
                "\nEarly stopping triggered."
            )

            break

    # =====================================================
    # RESTORE BEST MODEL
    # =====================================================

    if best_state is None:

        raise RuntimeError(
            "No valid model checkpoint was created."
        )

    model.load_state_dict(
        best_state
    )

    # =====================================================
    # FINAL TEST
    # =====================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "FINAL LEAKAGE-SAFE TEST EVALUATION"
    )

    print(
        "=" * 70
    )

    model.eval()

    with torch.no_grad():

        # -------------------------------------------------
        # IMPORTANT:
        #
        # Test edges are NOT used for message passing.
        # -------------------------------------------------

        _, embeddings = model(
            x,
            train_message_passing_edges,
            train_message_passing_edges
        )

        test_logits = classify_edges(
            model,
            embeddings,
            edge_index,
            test_indices
        )

        test_predictions = torch.argmax(
            test_logits,
            dim=1
        )

    test_labels = labels[
        test_indices
    ]

    test_metrics = calculate_metrics(
        test_labels,
        test_predictions
    )

    # =====================================================
    # CONFUSION MATRIX
    # =====================================================

    y_true = test_labels.cpu().numpy()

    y_pred = test_predictions.cpu().numpy()

    matrix = confusion_matrix(
        y_true,
        y_pred
    )

    # =====================================================
    # DISPLAY RESULTS
    # =====================================================

    print(
        f"\nAccuracy:  "
        f"{test_metrics['accuracy']:.4f}"
    )

    print(
        f"Precision: "
        f"{test_metrics['precision']:.4f}"
    )

    print(
        f"Recall:    "
        f"{test_metrics['recall']:.4f}"
    )

    print(
        f"F1 Score:  "
        f"{test_metrics['f1']:.4f}"
    )

    print(
        "\nConfusion Matrix:"
    )

    print(
        matrix
    )

    # =====================================================
    # DETAILED COUNTS
    # =====================================================

    if matrix.shape == (2, 2):

        tn = matrix[0][0]

        fp = matrix[0][1]

        fn = matrix[1][0]

        tp = matrix[1][1]

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
    # SAVE MODEL
    # =====================================================

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    checkpoint = {

        "model_state_dict":
            model.state_dict(),

        "input_dim":
            input_dim,

        "hidden_dim":
            HIDDEN_DIM,

        "heads":
            HEADS,

        "dropout":
            DROPOUT,

        "feature_mean":
            feature_mean.cpu(),

        "feature_std":
            feature_std.cpu(),

        "feature_names":
            graph["feature_names"],

        "best_val_f1":
            best_val_f1,

        "test_accuracy":
            test_metrics[
                "accuracy"
            ],

        "test_precision":
            test_metrics[
                "precision"
            ],

        "test_recall":
            test_metrics[
                "recall"
            ],

        "test_f1":
            test_metrics[
                "f1"
            ],

        "message_passing":
            "training_edges_only",

        "graph_type":
            "leakage_safe"
    }

    torch.save(
        checkpoint,
        MODEL_PATH
    )

    print(
        "\nModel saved to:"
    )

    print(
        MODEL_PATH
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "LEAKAGE-SAFE GAT TRAINING COMPLETE"
    )

    print(
        "=" * 70
    )


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    train()
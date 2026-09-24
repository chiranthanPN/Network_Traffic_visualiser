import torch

from app.models.gat_inference import GATInference


def main():

    print("=" * 70)
    print("GAT INFERENCE VALIDATION")
    print("=" * 70)

    # ---------------------------------------------------------
    # Load inference engine
    # ---------------------------------------------------------
    detector = GATInference()

    graph = detector.graph

    edge_index = graph["edge_index"]
    edge_labels = graph["edge_labels"]
    test_indices = graph["test_indices"]

    # ---------------------------------------------------------
    # Convert indices to CPU
    # ---------------------------------------------------------
    test_indices = test_indices.cpu()
    edge_index = edge_index.cpu()
    edge_labels = edge_labels.cpu()

    # ---------------------------------------------------------
    # Separate benign and attack test edges
    # ---------------------------------------------------------
    benign_indices = [
        int(i)
        for i in test_indices
        if int(edge_labels[i]) == 0
    ]

    attack_indices = [
        int(i)
        for i in test_indices
        if int(edge_labels[i]) == 1
    ]

    print(f"\nTest edges:      {len(test_indices)}")
    print(f"Benign test:     {len(benign_indices)}")
    print(f"Attack test:     {len(attack_indices)}")

    # ---------------------------------------------------------
    # Test a few edges
    # ---------------------------------------------------------
    selected_indices = (
        benign_indices[:3] +
        attack_indices[:3]
    )

    print("\n" + "=" * 70)
    print("EDGE PREDICTIONS")
    print("=" * 70)

    for edge_id in selected_indices:

        source_index = int(edge_index[0, edge_id])
        destination_index = int(edge_index[1, edge_id])

        source_ip = detector.index_to_ip[source_index]
        destination_ip = detector.index_to_ip[destination_index]

        actual_label = int(edge_labels[edge_id])

        result = detector.predict_edge(
            source_ip=source_ip,
            destination_ip=destination_ip
        )

        predicted_label = int(
            result["is_anomaly"]
        )

        print("\n" + "-" * 70)
        print(f"Edge ID:          {edge_id}")
        print(f"Source IP:        {source_ip}")
        print(f"Destination IP:   {destination_ip}")

        print(
            f"Actual label:     "
            f"{'ATTACK' if actual_label == 1 else 'BENIGN'}"
        )

        print(
            f"Attack score:     "
            f"{result['attack_score']:.4f}"
        )

        print(
            f"Threshold:        "
            f"{result['threshold']:.2f}"
        )

        print(
            f"Prediction:       "
            f"{'ATTACK' if predicted_label == 1 else 'BENIGN'}"
        )

        print(
            f"Correct:          "
            f"{'YES' if actual_label == predicted_label else 'NO'}"
        )

    print("\n" + "=" * 70)
    print("VALIDATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
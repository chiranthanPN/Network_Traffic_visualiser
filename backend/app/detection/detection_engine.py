import joblib
import torch
from pathlib import Path

from app.models.gat_inference import GATInference
from app.graph.live_graph_builder import LiveGraphBuilder


class DetectionEngine:
    """
    Central anomaly detection engine.

    AI Models:
        1. Isolation Forest
        2. Leakage-safe GAT

    Fusion:
        Combines both model decisions for each
        communication flow.
    """

    # =============================================================
    # ISOLATION FOREST FEATURES
    # =============================================================

    ISOLATION_FEATURES = [
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

    def __init__(
        self,
        isolation_forest_path=(
            "trained_models/isolation_forest.pkl"
        )
    ):

        self.isolation_forest_path = Path(
            isolation_forest_path
        )

        # =========================================================
        # LOAD ISOLATION FOREST
        # =========================================================

        print("=" * 70)
        print("INITIALIZING DETECTION ENGINE")
        print("=" * 70)

        print("\nLoading Isolation Forest...")

        self.isolation_forest = joblib.load(
            self.isolation_forest_path
        )

        print("Isolation Forest loaded.")

        # =========================================================
        # LOAD GAT
        # =========================================================

        print("\nLoading GAT...")

        self.gat = GATInference()

        print("GAT loaded.")

        # =========================================================
        # LIVE GRAPH BUILDER
        # =========================================================

        self.graph_builder = LiveGraphBuilder()

        print("Live Graph Builder loaded.")

        print("\n" + "=" * 70)
        print("DETECTION ENGINE READY")
        print("=" * 70)

    # =============================================================
    # EXTRACT ISOLATION FOREST FEATURES
    # =============================================================

    def _extract_isolation_features(self, flow):

        values = []

        for feature_name in self.ISOLATION_FEATURES:

            value = flow.get(
                feature_name,
                0
            )

            # Convert missing / invalid values to 0
            try:
                value = float(value)
            except (TypeError, ValueError):
                value = 0.0

            values.append(value)

        return values

    # =============================================================
    # ISOLATION FOREST INFERENCE
    # =============================================================

    def _run_isolation_forest(self, flows):

        if not flows:
            return []

        feature_matrix = [
            self._extract_isolation_features(flow)
            for flow in flows
        ]

        # ---------------------------------------------------------
        # Isolation Forest prediction
        #
        #  1  = normal
        # -1  = anomaly
        # ---------------------------------------------------------

        predictions = self.isolation_forest.predict(
            feature_matrix
        )

        # ---------------------------------------------------------
        # decision_function
        #
        # Higher value = more normal
        # Lower value  = more anomalous
        #
        # This is NOT a probability.
        # ---------------------------------------------------------

        decision_scores = (
            self.isolation_forest.decision_function(
                feature_matrix
            )
        )

        results = []

        for index, flow in enumerate(flows):

            prediction = int(
                predictions[index]
            )

            decision_score = float(
                decision_scores[index]
            )

            is_anomaly = (
                prediction == -1
            )

            results.append({
                "is_anomaly": is_anomaly,
                "decision_score": decision_score
            })

        return results

    # =============================================================
    # GAT INFERENCE
    # =============================================================

    def _run_gat(self, flows):

        if not flows:
            return {}

        # ---------------------------------------------------------
        # Build live graph
        # ---------------------------------------------------------

        graph = self.graph_builder.build(
            flows
        )

        if graph is None:
            return {}

        # ---------------------------------------------------------
        # Run GAT
        # ---------------------------------------------------------

        gat_results = self.gat.predict_live_graph(
            graph
        )

        # ---------------------------------------------------------
        # Convert results into:
        #
        # (source_ip, destination_ip)
        #
        # → GAT result
        # ---------------------------------------------------------

        gat_lookup = {}

        for result in gat_results:

            key = (
                result["source_ip"],
                result["destination_ip"]
            )

            gat_lookup[key] = result

        return gat_lookup

    # =============================================================
    # FUSION
    # =============================================================

    @staticmethod
    def _fuse_results(
        isolation_result,
        gat_result
    ):

        isolation_anomaly = (
            isolation_result["is_anomaly"]
        )

        gat_anomaly = False

        if gat_result is not None:

            gat_anomaly = (
                gat_result["is_anomaly"]
            )

        # ---------------------------------------------------------
        # BOTH MODELS FLAG ANOMALY
        # ---------------------------------------------------------

        if isolation_anomaly and gat_anomaly:

            risk_level = "HIGH"

        # ---------------------------------------------------------
        # ONLY ONE MODEL FLAGS ANOMALY
        # ---------------------------------------------------------

        elif isolation_anomaly or gat_anomaly:

            risk_level = "MEDIUM"

        # ---------------------------------------------------------
        # BOTH MODELS CONSIDER TRAFFIC NORMAL
        # ---------------------------------------------------------

        else:

            risk_level = "LOW"

        return {
            "isolation_forest_anomaly": (
                isolation_anomaly
            ),
            "gat_anomaly": (
                gat_anomaly
            ),
            "risk_level": risk_level
        }

    # =============================================================
    # ANALYZE FLOWS
    # =============================================================

    def analyze(self, flows):

        if not flows:

            return {
                "total_flows": 0,
                "anomalies": 0,
                "results": []
            }

        # =========================================================
        # ISOLATION FOREST
        # =========================================================

        isolation_results = (
            self._run_isolation_forest(
                flows
            )
        )

        # =========================================================
        # GAT
        # =========================================================

        gat_results = self._run_gat(
            flows
        )

        # =========================================================
        # FUSION
        # =========================================================

        final_results = []

        for index, flow in enumerate(flows):

            source_ip = flow.get(
                "source_ip"
            )

            destination_ip = flow.get(
                "destination_ip"
            )

            # -----------------------------------------------------
            # Find GAT result for this communication pair
            # -----------------------------------------------------

            gat_key = (
                source_ip,
                destination_ip
            )

            gat_result = gat_results.get(
                gat_key
            )

            # -----------------------------------------------------
            # Fusion
            # -----------------------------------------------------

            fusion = self._fuse_results(
                isolation_results[index],
                gat_result
            )

            # -----------------------------------------------------
            # Final result
            # -----------------------------------------------------

            result = {
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "source_port": flow.get(
                    "source_port"
                ),
                "destination_port": flow.get(
                    "destination_port"
                ),
                "protocol": flow.get(
                    "protocol"
                ),
                "packet_count": flow.get(
                    "packet_count",
                    0
                ),
                "byte_count": flow.get(
                    "byte_count",
                    0
                ),

                # Isolation Forest
                "isolation_forest": {
                    "is_anomaly": (
                        isolation_results[index][
                            "is_anomaly"
                        ]
                    ),
                    "decision_score": (
                        isolation_results[index][
                            "decision_score"
                        ]
                    )
                },

                # GAT
                "gat": {
                    "is_anomaly": (
                        gat_result["is_anomaly"]
                        if gat_result
                        else False
                    ),
                    "attack_score": (
                        gat_result["attack_score"]
                        if gat_result
                        else 0.0
                    ),
                    "threshold": (
                        gat_result["threshold"]
                        if gat_result
                        else self.gat.threshold
                    )
                },

                # Fusion
                "fusion": fusion
            }

            final_results.append(
                result
            )

        # =========================================================
        # COUNT ANOMALIES
        # =========================================================

        anomaly_count = sum(
            1
            for result in final_results
            if result["fusion"]["risk_level"]
            != "LOW"
        )

        return {
            "total_flows": len(flows),
            "anomalies": anomaly_count,
            "results": final_results
        }


# =================================================================
# TEST
# =================================================================

if __name__ == "__main__":

    print("\n")

    # -------------------------------------------------------------
    # Create detection engine
    # -------------------------------------------------------------

    engine = DetectionEngine()

    # -------------------------------------------------------------
    # Simulated flow data
    # -------------------------------------------------------------

    test_flows = [

        {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "source_port": 50000,
            "destination_port": 53,
            "protocol": "UDP",

            "packet_count": 10,
            "byte_count": 1000,
            "duration": 1.0,

            "packets_per_second": 10.0,
            "bytes_per_second": 1000.0,

            "average_packet_size": 100.0,

            "unique_destination_ips": 1,
            "unique_destination_ports": 1,

            "tcp_syn_count": 0,
            "tcp_rst_count": 0
        },

        {
            "source_ip": "192.168.1.10",
            "destination_ip": "1.1.1.1",
            "source_port": 50001,
            "destination_port": 443,
            "protocol": "TCP",

            "packet_count": 5,
            "byte_count": 500,
            "duration": 2.0,

            "packets_per_second": 2.5,
            "bytes_per_second": 250.0,

            "average_packet_size": 100.0,

            "unique_destination_ips": 1,
            "unique_destination_ports": 1,

            "tcp_syn_count": 1,
            "tcp_rst_count": 0
        }
    ]

    # -------------------------------------------------------------
    # Analyze
    # -------------------------------------------------------------

    results = engine.analyze(
        test_flows
    )

    # -------------------------------------------------------------
    # Display results
    # -------------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("DETECTION ENGINE TEST")
    print("=" * 70)

    print(
        f"Total flows: {results['total_flows']}"
    )

    print(
        f"Anomalies:   {results['anomalies']}"
    )

    for index, result in enumerate(
        results["results"],
        start=1
    ):

        print("\n" + "-" * 70)

        print(
            f"FLOW {index}"
        )

        print(
            f"Source:        "
            f"{result['source_ip']}"
        )

        print(
            f"Destination:   "
            f"{result['destination_ip']}"
        )

        print(
            f"Protocol:      "
            f"{result['protocol']}"
        )

        print(
            f"Packets:       "
            f"{result['packet_count']}"
        )

        print(
            f"Bytes:         "
            f"{result['byte_count']}"
        )

        print("\nIsolation Forest:")

        print(
            f"  Anomaly:     "
            f"{result['isolation_forest']['is_anomaly']}"
        )

        print(
            f"  Score:       "
            f"{result['isolation_forest']['decision_score']:.4f}"
        )

        print("\nGAT:")

        print(
            f"  Anomaly:     "
            f"{result['gat']['is_anomaly']}"
        )

        print(
            f"  Attack score:"
            f" {result['gat']['attack_score']:.4f}"
        )

        print(
            f"  Threshold:   "
            f"{result['gat']['threshold']:.2f}"
        )

        print("\nFusion:")

        print(
            f"  Isolation Forest:"
            f" {result['fusion']['isolation_forest_anomaly']}"
        )

        print(
            f"  GAT:"
            f" {result['fusion']['gat_anomaly']}"
        )

        print(
            f"  Risk level:"
            f" {result['fusion']['risk_level']}"
        )

    print("\n")
    print("=" * 70)
    print("DETECTION ENGINE TEST COMPLETE")
    print("=" * 70)
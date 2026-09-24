from datetime import datetime


class AlertManager:
    """
    Converts DetectionEngine results into clean
    security events for the API/dashboard.

    Risk levels:
        LOW
        MEDIUM
        HIGH
    """

    def __init__(self, max_alerts=1000):

        self.max_alerts = max_alerts
        self.alerts = []

    # =============================================================
    # CREATE EVENT
    # =============================================================

    def create_event(self, result):

        event = {
            "timestamp": datetime.now().isoformat(
                timespec="seconds"
            ),

            "source_ip": result.get(
                "source_ip"
            ),

            "destination_ip": result.get(
                "destination_ip"
            ),

            "source_port": result.get(
                "source_port"
            ),

            "destination_port": result.get(
                "destination_port"
            ),

            "protocol": result.get(
                "protocol"
            ),

            "packet_count": result.get(
                "packet_count",
                0
            ),

            "byte_count": result.get(
                "byte_count",
                0
            ),

            # -----------------------------------------------------
            # Isolation Forest
            # -----------------------------------------------------

            "isolation_forest": {
                "is_anomaly": result[
                    "isolation_forest"
                ][
                    "is_anomaly"
                ],

                "decision_score": result[
                    "isolation_forest"
                ][
                    "decision_score"
                ]
            },

            # -----------------------------------------------------
            # GAT
            # -----------------------------------------------------

            "gat": {
                "is_anomaly": result[
                    "gat"
                ][
                    "is_anomaly"
                ],

                "attack_score": result[
                    "gat"
                ][
                    "attack_score"
                ],

                "threshold": result[
                    "gat"
                ][
                    "threshold"
                ]
            },

            # -----------------------------------------------------
            # Fusion
            # -----------------------------------------------------

            "risk_level": result[
                "fusion"
            ][
                "risk_level"
            ]
        }

        return event

    # =============================================================
    # ADD EVENT
    # =============================================================

    def add_event(self, result):

        event = self.create_event(
            result
        )

        self.alerts.append(
            event
        )

        # ---------------------------------------------------------
        # Keep memory bounded
        # ---------------------------------------------------------

        if len(self.alerts) > self.max_alerts:

            self.alerts = self.alerts[
                -self.max_alerts:
            ]

        return event

    # =============================================================
    # PROCESS DETECTION RESULTS
    # =============================================================

    def process_results(
        self,
        detection_results
    ):

        events = []

        for result in detection_results.get(
            "results",
            []
        ):

            event = self.add_event(
                result
            )

            events.append(
                event
            )

        return events

    # =============================================================
    # GET ALL EVENTS
    # =============================================================

    def get_events(self):

        return list(
            self.alerts
        )

    # =============================================================
    # GET ONLY ALERTS
    #
    # LOW risk is ignored.
    # MEDIUM and HIGH are returned.
    # =============================================================

    def get_alerts(self):

        return [
            event
            for event in self.alerts
            if event["risk_level"]
            in (
                "MEDIUM",
                "HIGH"
            )
        ]

    # =============================================================
    # GET RECENT EVENTS
    # =============================================================

    def get_recent_events(
        self,
        limit=20
    ):

        return self.alerts[
            -limit:
        ]

    # =============================================================
    # GET RECENT ALERTS
    # =============================================================

    def get_recent_alerts(
        self,
        limit=20
    ):

        alerts = self.get_alerts()

        return alerts[
            -limit:
        ]

    # =============================================================
    # STATISTICS
    # =============================================================

    def get_statistics(self):

        low = 0
        medium = 0
        high = 0

        for event in self.alerts:

            risk = event[
                "risk_level"
            ]

            if risk == "LOW":

                low += 1

            elif risk == "MEDIUM":

                medium += 1

            elif risk == "HIGH":

                high += 1

        total = (
            low +
            medium +
            high
        )

        return {
            "total_events": total,
            "low": low,
            "medium": medium,
            "high": high,
            "total_alerts": (
                medium + high
            )
        }

    # =============================================================
    # CLEAR EVENTS
    # =============================================================

    def clear(self):

        self.alerts.clear()


# =================================================================
# TEST
# =================================================================

if __name__ == "__main__":

    manager = AlertManager()

    # -------------------------------------------------------------
    # Fake detection result
    # -------------------------------------------------------------

    test_results = {
        "total_flows": 2,

        "anomalies": 1,

        "results": [

            {
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",

                "source_port": 50000,
                "destination_port": 53,

                "protocol": "UDP",

                "packet_count": 10,
                "byte_count": 1000,

                "isolation_forest": {
                    "is_anomaly": False,
                    "decision_score": 0.1282
                },

                "gat": {
                    "is_anomaly": False,
                    "attack_score": 0.5499,
                    "threshold": 0.80
                },

                "fusion": {
                    "isolation_forest_anomaly": False,
                    "gat_anomaly": False,
                    "risk_level": "LOW"
                }
            },

            {
                "source_ip": "10.20.184.227",
                "destination_ip": "104.18.125.108",

                "source_port": 54532,
                "destination_port": 443,

                "protocol": "TCP",

                "packet_count": 7,
                "byte_count": 882,

                "isolation_forest": {
                    "is_anomaly": True,
                    "decision_score": -0.0546
                },

                "gat": {
                    "is_anomaly": False,
                    "attack_score": 0.5509,
                    "threshold": 0.80
                },

                "fusion": {
                    "isolation_forest_anomaly": True,
                    "gat_anomaly": False,
                    "risk_level": "MEDIUM"
                }
            }
        ]
    }

    # -------------------------------------------------------------
    # Process
    # -------------------------------------------------------------

    events = manager.process_results(
        test_results
    )

    # -------------------------------------------------------------
    # Display
    # -------------------------------------------------------------

    print("=" * 70)
    print("ALERT MANAGER TEST")
    print("=" * 70)

    print(
        f"\nEvents created: "
        f"{len(events)}"
    )

    print("\nStatistics:")

    print(
        manager.get_statistics()
    )

    print("\nRecent alerts:")

    for alert in manager.get_recent_alerts():

        print("\n" + "-" * 70)

        print(
            f"Time:          "
            f"{alert['timestamp']}"
        )

        print(
            f"Source:        "
            f"{alert['source_ip']}"
        )

        print(
            f"Destination:   "
            f"{alert['destination_ip']}"
        )

        print(
            f"Protocol:      "
            f"{alert['protocol']}"
        )

        print(
            f"Risk:           "
            f"{alert['risk_level']}"
        )

        print(
            f"IF anomaly:    "
            f"{alert['isolation_forest']['is_anomaly']}"
        )

        print(
            f"GAT anomaly:   "
            f"{alert['gat']['is_anomaly']}"
        )

    print("\n" + "=" * 70)
    print("ALERT MANAGER TEST COMPLETE")
    print("=" * 70)
from feature_extractor import FlowProcessor


processor = FlowProcessor(window_size=5)


# Simulate packet 1
processor.process_packet(
    source_ip="192.168.1.10",
    destination_ip="8.8.8.8",
    protocol="TCP",
    packet_size=1000,
    destination_port=443,
    tcp_syn=True
)


# Simulate packet 2
processor.process_packet(
    source_ip="192.168.1.10",
    destination_ip="8.8.8.8",
    protocol="TCP",
    packet_size=1500,
    destination_port=443
)


# Simulate packet 3
processor.process_packet(
    source_ip="192.168.1.10",
    destination_ip="1.1.1.1",
    protocol="TCP",
    packet_size=800,
    destination_port=443
)


features = processor.get_features()


for feature in features:

    print("\n===== FLOW FEATURES =====")

    for key, value in feature.items():

        print(f"{key}: {value}")
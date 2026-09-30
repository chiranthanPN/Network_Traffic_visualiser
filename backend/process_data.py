import pandas as pd
import numpy as np

print("Generating mixed-risk flow dataset (Low, Medium, High)...")

def generate_mixed_dataset(total_rows=1500):
    rows = []
    
    # Target proportions:
    # 50% Low Risk (Normal Traffic)
    # 25% Medium Risk (Port Scans, Login Bursts, DNS Bursts)
    # 25% High Risk (SYN Floods, Heavy DDoS Floods, Massive Transfers)
    n_low = int(total_rows * 0.50)
    n_med = int(total_rows * 0.25)
    n_high = total_rows - n_low - n_med
    
    # ---------------- 1. LOW RISK (Normal Traffic) ----------------
    for _ in range(n_low):
        src_ip = f"192.168.1.{np.random.randint(10, 40)}"
        dst_ip = np.random.choice(["142.250.72.14", "1.1.1.1", "8.8.8.8", "151.101.1.69"])
        src_port = np.random.randint(49152, 65535)
        dst_port = np.random.choice([80, 443, 53, 123])
        protocol = "UDP" if dst_port in [53, 123] else "TCP"
        
        pkts = int(np.random.randint(2, 25))
        bytes_len = int(pkts * np.random.randint(60, 800))
        dur = round(float(np.random.uniform(0.5, 4.0)), 3)
        pps = round(pkts / dur, 2)
        bps = round(bytes_len / dur, 2)
        
        rows.append({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": protocol,
            "packet_count": pkts,
            "byte_count": bytes_len,
            "duration": dur,
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "average_packet_size": round(bytes_len / pkts, 2),
            "unique_destination_ips": 1,
            "unique_destination_ports": 1,
            "tcp_syn_count": np.random.choice([0, 1]),
            "tcp_rst_count": 0,
            "scenario": "ordinary_traffic",
            "expected_label": "NORMAL"
        })

    # ---------------- 2. MEDIUM RISK (Scans & Bursts) ----------------
    for _ in range(n_med):
        scenario = np.random.choice(["port_scan", "login_burst", "dns_burst"])
        src_ip = f"192.168.1.{np.random.randint(45, 60)}"
        
        if scenario == "port_scan":
            dst_ip = "10.0.0.5"
            src_port = np.random.randint(49152, 65535)
            dst_port = int(np.random.randint(20, 1024))
            pkts = 1
            bytes_len = 60
            dur = 0.001
            syn = 1
            uniq_ports = int(np.random.randint(15, 60))
            uniq_ips = 1
        elif scenario == "login_burst":
            dst_ip = "10.0.0.2"
            src_port = np.random.randint(49152, 65535)
            dst_port = 22
            pkts = int(np.random.randint(500, 1200))
            bytes_len = int(pkts * 70)
            dur = round(float(np.random.uniform(15.0, 30.0)), 3)
            syn = int(pkts * 0.3)
            uniq_ports = 1
            uniq_ips = 1
        else: # dns_burst
            dst_ip = "1.1.1.1"
            src_port = np.random.randint(49152, 65535)
            dst_port = 53
            pkts = int(np.random.randint(2000, 5000))
            bytes_len = int(pkts * 250)
            dur = round(float(np.random.uniform(5.0, 12.0)), 3)
            syn = 0
            uniq_ports = 1
            uniq_ips = 1

        pps = round(pkts / dur, 2)
        bps = round(bytes_len / dur, 2)

        rows.append({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": "TCP" if scenario != "dns_burst" else "UDP",
            "packet_count": pkts,
            "byte_count": bytes_len,
            "duration": dur,
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "average_packet_size": round(bytes_len / pkts, 2),
            "unique_destination_ips": uniq_ips,
            "unique_destination_ports": uniq_ports,
            "tcp_syn_count": syn,
            "tcp_rst_count": 0,
            "scenario": scenario,
            "expected_label": "SYNTHETIC_ANOMALY"
        })

    # ---------------- 3. HIGH RISK (DDoS & SYN Floods) ----------------
    for _ in range(n_high):
        scenario = np.random.choice(["traffic_flood", "syn_flood", "large_exfiltration"])
        src_ip = f"192.168.1.{np.random.randint(100, 200)}"
        dst_ip = "10.0.0.1"
        src_port = np.random.randint(49152, 65535)
        dst_port = int(np.random.choice([80, 443, 8080]))
        
        if scenario == "syn_flood":
            pkts = int(np.random.randint(15000, 35000))
            bytes_len = int(pkts * 64)
            dur = round(float(np.random.uniform(2.0, 6.0)), 3)
            syn = int(pkts * 0.85) # High SYN count triggers alert
            uniq_ips = int(np.random.randint(5, 20))
            uniq_ports = int(np.random.randint(5, 10))
        elif scenario == "traffic_flood":
            pkts = int(np.random.randint(20000, 50000))
            bytes_len = int(pkts * 500)
            dur = round(float(np.random.uniform(3.0, 8.0)), 3)
            syn = int(pkts * 0.4)
            uniq_ips = int(np.random.randint(10, 30))
            uniq_ports = 1
        else: # large_exfiltration
            pkts = int(np.random.randint(30000, 60000))
            bytes_len = int(pkts * 1400)
            dur = round(float(np.random.uniform(10.0, 40.0)), 3)
            syn = 2
            uniq_ips = 1
            uniq_ports = 1

        pps = round(pkts / dur, 2)
        bps = round(bytes_len / dur, 2)

        rows.append({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": "TCP",
            "packet_count": pkts,
            "byte_count": bytes_len,
            "duration": dur,
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "average_packet_size": round(bytes_len / pkts, 2),
            "unique_destination_ips": uniq_ips,
            "unique_destination_ports": uniq_ports,
            "tcp_syn_count": syn,
            "tcp_rst_count": np.random.choice([0, 1]),
            "scenario": scenario,
            "expected_label": "SYNTHETIC_ANOMALY"
        })

    # Shuffle to interleave normal, medium, and high-risk packets naturally
    df_out = pd.DataFrame(rows).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df_out

# Generate datasets
df_demo = generate_mixed_dataset(total_rows=1000)

# Build normal_traffic matching 15-column schema
normal_cols = [c for c in df_demo.columns if c not in ["scenario", "expected_label"]]
df_normal = df_demo[df_demo["expected_label"] == "NORMAL"][normal_cols].reset_index(drop=True)

# Save to backend data directory
df_demo.to_csv("data/demo_anomaly_flows.csv", index=False)
df_normal.to_csv("data/normal_traffic.csv", index=False)

print(f"Generated demo_anomaly_flows.csv with {len(df_demo)} rows and 0 null values.")
print(f"Generated normal_traffic.csv with {len(df_normal)} rows.")
print("Risk profile breakdown:")
print(df_demo['scenario'].value_counts())
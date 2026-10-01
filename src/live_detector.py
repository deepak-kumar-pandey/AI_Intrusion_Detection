import os
import time
import warnings
import joblib
import pandas as pd
import numpy as np
from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Suppress harmless scikit-learn feature name mismatch warnings
warnings.filterwarnings("ignore", category=UserWarning)

MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')

print("Loading detection artifacts...")
model = joblib.load(os.path.join(MODEL_DIR, 'random_forest_model.pkl'))
scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
label_encoder = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.pkl'))
feature_names = joblib.load(os.path.join(MODEL_DIR, 'feature_names.pkl'))
print("Artifacts loaded successfully.\n")

active_flows = {}

def extract_flow_features(packet):
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
    
    src_port = packet.sport if hasattr(packet, 'sport') else 0
    dst_port = packet.dport if hasattr(packet, 'dport') else 0
    pkt_len = len(packet)
    now = time.time()

    flow_key = (src_ip, dst_ip, src_port, dst_port, proto)

    if flow_key not in active_flows:
        active_flows[flow_key] = {
            'start_time': now,
            'last_time': now,
            'fwd_pkts': 1,
            'fwd_lengths': [pkt_len],
            'dst_port': dst_port
        }
    else:
        flow = active_flows[flow_key]
        flow['last_time'] = now
        flow['fwd_pkts'] += 1
        flow['fwd_lengths'].append(pkt_len)

    flow = active_flows[flow_key]
    duration_micros = (flow['last_time'] - flow['start_time']) * 1_000_000
    lengths = flow['fwd_lengths']

    row = {col: 0.0 for col in feature_names}

    for col in feature_names:
        c_lower = col.lower()
        if 'destination port' in c_lower or 'dest port' in c_lower:
            row[col] = float(flow['dst_port'])
        elif 'flow duration' in c_lower:
            row[col] = float(duration_micros)
        elif 'total fwd packets' in c_lower:
            row[col] = float(flow['fwd_pkts'])
        elif 'total length of fwd packets' in c_lower:
            row[col] = float(sum(lengths))
        elif 'fwd packet length max' in c_lower:
            row[col] = float(max(lengths))
        elif 'fwd packet length min' in c_lower:
            row[col] = float(min(lengths))
        elif 'fwd packet length mean' in c_lower:
            row[col] = float(np.mean(lengths))
        elif 'fwd packet length std' in c_lower:
            row[col] = float(np.std(lengths)) if len(lengths) > 1 else 0.0

    return (src_ip, dst_ip, dst_port, proto, row)

def classify_packet(packet):
    result = extract_flow_features(packet)
    if result is None:
        return

    src_ip, dst_ip, dst_port, proto, feature_dict = result

    df_features = pd.DataFrame([feature_dict])[feature_names]
    scaled_vector = scaler.transform(df_features)
    
    # Re-wrap scaled vector with column names to keep scikit-learn satisfied
    scaled_df = pd.DataFrame(scaled_vector, columns=feature_names)
    pred_idx = model.predict(scaled_df)[0]
    attack_label = label_encoder.inverse_transform([pred_idx])[0]

    timestamp = datetime.now().strftime("%H:%M:%S")

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    if attack_label == "Normal Traffic":
        print(f"[{timestamp}] {GREEN}[NORMAL]{RESET} {proto:<5} | {src_ip} -> {dst_ip}:{dst_port}")
    else:
        print(f"[{timestamp}] {RED}[ALERT - {attack_label.upper()}]{RESET} {YELLOW}{proto:<5}{RESET} | {src_ip} -> {dst_ip}:{dst_port}")

def main():
    print("=" * 65)
    print("      AI INTRUSION DETECTION SYSTEM — REAL-TIME MONITOR      ")
    print("=" * 65)
    print("Listening to network interface... (Press Ctrl+C to stop)\n")

    try:
        sniff(prn=classify_packet, store=False)
    except KeyboardInterrupt:
        print("\n[!] Live detection stopped by user.")
    except PermissionError:
        print("\n[!] Error: Administrative privileges required to capture packets.")

if __name__ == "__main__":
    main()
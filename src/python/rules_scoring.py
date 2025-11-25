import rules_extract
from rules_fft import fft_bytes_per_sec_conn, fft_conncount_per_sec_conn, fft_packets_per_sec_conn, fft_timestamps_per_sec_conn, extract_fft_ruleset_conn
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import deque
import time

conn_paths = [
        "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_conn.csv",           # [0]
        "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_conn.csv",           # [1]
        "../../train_test_data/benign_1_min/cam-pod/csv files/camera_conn.csv",                 # [2]
        "../../train_test_data/benign_1_min/lidar-pod/csv files/lidar_conn.csv",                # [3]
        "../../train_test_data/benign_1_min/nginx-pod/csv files/NGINX_conn.csv",                # [4]
        "../../train_test_data/benign_sim/csv/conn.csv",                                        # [5] benign
        "../../train_test_data/ddos_sim/csv/conn_malignant1.csv",                               # [6] malignant
        
        # NEW BENIGN DATA PATHS
        # "../../train_test_data/new-benign/csv/child1/conn.csv",                                 # [7]
        # "../../train_test_data/new-benign/csv/child2/conn.csv",                                 # [8]
        # "../../train_test_data/new-benign/csv/cam-pod/conn.csv",                                # [9]
        # "../../train_test_data/new-benign/csv/lidar-pod/conn.csv",                              # [10]
        # "../../train_test_data/new-benign/csv/nginx-pod/conn.csv",                              # [11]
        
        # NEW BENIGN DATA PATHS (10 MINUTE)
        "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",                                 # [7]
        "../../train_test_data/new-benign_10_min/csv/child2/conn.csv",                                 # [8]
        "../../train_test_data/new-benign_10_min/csv/cam-pod/conn.csv",                                # [9]
        "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv",                              # [10]
        "../../train_test_data/new-benign_10_min/csv/nginx-pod/conn.csv",                              # [11]
        
        
        # NEW MALIGNANT DATA PATHS
        "../../train_test_data/lidar-attack/csv/child1/conn.csv",                               # [12]
        "../../train_test_data/lidar-attack/csv/child2/conn.csv",                               # [13]
        "../../train_test_data/lidar-attack/csv/cam-pod/conn.csv",                              # [14]
        "../../train_test_data/lidar-attack/csv/lidar-pod/conn.csv",                            # [15]
        "../../train_test_data/lidar-attack/csv/nginx-pod/conn.csv",                            # [16]
        
        # COMBINED GENERALIZED BENIGN SET
        # "../../train_test_data/combined_benign_conn.csv"                                        # [17]
]

# ==== Calculate a rules score based on the log type for a SINGLE LINE ====
def get_rules_score_conn(line: str, ruleset: dict, from_buf: bool):
    # name the columns for a dictionary
    cols = [
        "ts",               # [0]
        "uid",              
        "id.orig_h",
        "id.orig_p",        # [3]
        "id.resp_h",
        "id.resp_p",        # [5]
        "proto",
        "service",
        "duration",         # [8]
        "orig_bytes",       # [9]
        "resp_bytes",       # [10]
        "conn_state",
        "local_orig",
        "local_resp",
        "missed_bytes",     # [14]
        "history",          
        "orig_pkts",        # [16]
        "orig_ip_bytes",    # [17]
        "resp_pkts",        # [18]
        "resp_ip_bytes",    # [19]
        "tunnel_parents"
    ]

    # format the line for the dictionary
    if(from_buf):
        line = line[5:] # strip 'CONN,' from front of line
    line = line.split(',')
    for i in range(len(line)):
        if line[i] == '-':
            line[i] = 0
        if line[i] == 'T':
            line[i] = 1
        if line[i] == 'F':
            line[i] = 0
        if i in [0, 3, 5, 8, 9, 10, 14, 16, 17, 18, 19]:    # numeric columns
            # print(line[i])
            line[i] = float(line[i])
            
    
    # make the dictionary
    line_data = dict(zip(cols, line))
    # print_dict(line_data)
    
    # run the logic checks and build the score
    anomaly_score = 0
    
    # (1) Known Origin Addresses/Ports
    # TODO: moot point for the type of attack we were given (for now)
    
    # (2) Known Response Addresses/Ports
    # TODO: moot point for the type of attack we were given (for now)
    
    # (3) Duration Behavior
    #   --> Long durations: 
    #   --> Short durations: 
    dur_score = 0
    if line_data['duration'] > ruleset['duration']['p99']:
        dur_score = 1
    elif line_data['duration'] > ruleset['duration']['p95']:
        dur_score = 0.5
    elif line_data['duration'] < ruleset['duration']['p01']:
        dur_score = 1
    elif line_data['duration'] < ruleset['duration']['p05']:
        dur_score = 0.5
    else:
        dur_score = 0
    
    # (4) Traffic Volume Behavior
    volume_score = 0
    if line_data['orig_bytes'] > 0 and line_data['resp_bytes'] > 0:             # Check if bidirectional traffic exists
        byte_ratio = line_data['orig_bytes'] / line_data['resp_bytes']
        if byte_ratio > ruleset['bytes']['bidirectional_p99']:
            volume_score = 1
        elif byte_ratio > ruleset['bytes']['bidirectional_p95']:
            volume_score = 0.5
        elif byte_ratio < ruleset['bytes']['bidirectional_p01']:
            volume_score = 1
        elif byte_ratio < ruleset['bytes']['bidirectional_p05']:
            volume_score = 0.5
        else:
            volume_score = 0
    
    elif line_data['orig_bytes'] > 0 and line_data['resp_bytes'] == 0:          # Check orig-only traffic
        if line_data['orig_bytes'] > ruleset['bytes']['orig_only_p99']:
            volume_score = 1
        elif line_data['orig_bytes'] > ruleset['bytes']['orig_only_p95']:
            volume_score = 0.5
        elif line_data['orig_bytes'] < ruleset['bytes']['orig_only_p01']:
            volume_score = 1
        elif line_data['orig_bytes'] < ruleset['bytes']['orig_only_p05']:
            volume_score = 0.5
        else:
            volume_score = 0
    
    elif line_data['resp_bytes'] > 0 and line_data['orig_bytes'] == 0:          # Check resp-only traffic
        if line_data['resp_bytes'] > ruleset['bytes']['resp_only_p99']:
            volume_score = 1
        elif line_data['resp_bytes'] > ruleset['bytes']['resp_only_p95']:
            volume_score = 0.5
        elif line_data['resp_bytes'] < ruleset['bytes']['resp_only_p01']:
            volume_score = 1
        elif line_data['resp_bytes'] < ruleset['bytes']['resp_only_p05']:
            volume_score = 0.5
        else:
            volume_score = 0
    
    
    # (5) Packet-Level Behavior
    packet_score = 0
    if line_data['orig_pkts'] > 0 and line_data['resp_pkts'] > 0:               # Check if bidirectional packet traffic exists
        pkt_ratio = line_data['orig_pkts'] / line_data['resp_pkts']
        if pkt_ratio > ruleset['packets']['bidirectional_p99']:
            packet_score = 1
        elif pkt_ratio > ruleset['packets']['bidirectional_p95']:
            packet_score = 0.5
        elif pkt_ratio < ruleset['packets']['bidirectional_p01']:
            packet_score = 1
        elif pkt_ratio < ruleset['packets']['bidirectional_p05']:
            packet_score = 0.5
        else:
            packet_score = 0
    elif line_data['orig_pkts'] > 0 and line_data['resp_pkts'] == 0:            # Check orig-only packet traffic
        if line_data['orig_pkts'] > ruleset['packets']['orig_only_p99']:
            packet_score = 1
        elif line_data['orig_pkts'] > ruleset['packets']['orig_only_p95']:
            packet_score = 0.5
        elif line_data['orig_pkts'] < ruleset['packets']['orig_only_p01']:
            packet_score = 1
        elif line_data['orig_pkts'] < ruleset['packets']['orig_only_p05']:
            packet_score = 0.5
        else:
            packet_score = 0
    
    elif line_data['resp_pkts'] > 0 and line_data['orig_pkts'] == 0:            # Check resp-only packet traffic
        if line_data['resp_pkts'] > ruleset['packets']['resp_only_p99']:
            packet_score = 1
        elif line_data['resp_pkts'] > ruleset['packets']['resp_only_p95']:
            packet_score = 0.5
        elif line_data['resp_pkts'] < ruleset['packets']['resp_only_p01']:
            packet_score = 1
        elif line_data['resp_pkts'] < ruleset['packets']['resp_only_p05']:
            packet_score = 0.5
        else:
            packet_score = 0
            
    # (6) Byte Rate Behavior
    bps_score = 0
    if line_data['duration'] > 0:
        if line_data['orig_bytes'] > 0 and line_data['resp_bytes'] > 0:             # Check if bidirectional traffic exists
            bidirectional_bps = (line_data['orig_bytes'] + line_data['resp_bytes']) / line_data['duration']
            if bidirectional_bps > ruleset['rate_data']['bytes_per_second']['bidirectional_p99']:
                bps_score = 1
            elif bidirectional_bps > ruleset['rate_data']['bytes_per_second']['bidirectional_p95']:
                bps_score = 0.5
            elif bidirectional_bps < ruleset['rate_data']['bytes_per_second']['bidirectional_p01']:
                bps_score = 1
            elif bidirectional_bps < ruleset['rate_data']['bytes_per_second']['bidirectional_p05']:
                bps_score = 0.5
            else:
                bps_score = 0
        
        elif line_data['orig_bytes'] > 0 and line_data['resp_bytes'] == 0:          # Check orig-only traffic
            orig_only_bps = line_data['orig_bytes'] / line_data['duration']
            if orig_only_bps > ruleset['rate_data']['bytes_per_second']['orig_only_p99']:
                bps_score = 1
            elif orig_only_bps > ruleset['rate_data']['bytes_per_second']['orig_only_p95']:
                bps_score = 0.5
            elif orig_only_bps < ruleset['rate_data']['bytes_per_second']['orig_only_p01']:
                bps_score = 1
            elif orig_only_bps < ruleset['rate_data']['bytes_per_second']['orig_only_p05']:
                bps_score = 0.5
            else:
                bps_score = 0
        
        elif line_data['resp_bytes'] > 0 and line_data['orig_bytes'] == 0:          # Check resp-only traffic
            resp_only_bps = line_data['resp_bytes'] / line_data['duration']
            if resp_only_bps > ruleset['rate_data']['bytes_per_second']['resp_only_p99']:
                bps_score = 1
            elif resp_only_bps > ruleset['rate_data']['bytes_per_second']['resp_only_p95']:
                bps_score = 0.5
            elif resp_only_bps < ruleset['rate_data']['bytes_per_second']['resp_only_p01']:
                bps_score = 1
            elif resp_only_bps < ruleset['rate_data']['bytes_per_second']['resp_only_p05']:
                bps_score = 0.5
            else:
                bps_score = 0
    
    # (7) Packet Rate Behavior
    pps_score = 0
    if line_data['duration'] > 0:
        if line_data['orig_pkts'] > 0 and line_data['resp_pkts'] > 0:               # Check if bidirectional packet traffic exists
            bidirectional_pps = (line_data['orig_pkts'] + line_data['resp_pkts']) / line_data['duration']
            if bidirectional_pps > ruleset['rate_data']['packets_per_second']['bidirectional_p99']:
                pps_score = 1
            elif bidirectional_pps > ruleset['rate_data']['packets_per_second']['bidirectional_p95']:
                pps_score = 0.5
            elif bidirectional_pps < ruleset['rate_data']['packets_per_second']['bidirectional_p01']:
                pps_score = 1
            elif bidirectional_pps < ruleset['rate_data']['packets_per_second']['bidirectional_p05']:
                pps_score = 0.5
            else:
                pps_score = 0
        
        elif line_data['orig_pkts'] > 0 and line_data['resp_pkts'] == 0:            # Check orig-only packet traffic
            orig_only_pps = line_data['orig_pkts'] / line_data['duration']
            if orig_only_pps > ruleset['rate_data']['packets_per_second']['orig_only_p99']:
                pps_score = 1
            elif orig_only_pps > ruleset['rate_data']['packets_per_second']['orig_only_p95']:
                pps_score = 0.5
            elif orig_only_pps < ruleset['rate_data']['packets_per_second']['orig_only_p01']:
                pps_score = 1
            elif orig_only_pps < ruleset['rate_data']['packets_per_second']['orig_only_p05']:
                pps_score = 0.5
            else:
                pps_score = 0
        
        elif line_data['resp_pkts'] > 0 and line_data['orig_pkts'] == 0:            # Check resp-only packet traffic
            resp_only_pps = line_data['resp_pkts'] / line_data['duration']
            if resp_only_pps > ruleset['rate_data']['packets_per_second']['resp_only_p99']:
                pps_score = 1
            elif resp_only_pps > ruleset['rate_data']['packets_per_second']['resp_only_p95']:
                pps_score = 0.5
            elif resp_only_pps < ruleset['rate_data']['packets_per_second']['resp_only_p01']:
                pps_score = 1
            elif resp_only_pps < ruleset['rate_data']['packets_per_second']['resp_only_p05']:
                pps_score = 0.5
            else:
                pps_score = 0
        
    

    # anomaly_score = (dur_score + volume_score + packet_score + bps_score + pps_score) / 5  
    
    anomaly_score += dur_score * 0.1
    anomaly_score += volume_score * 0.1
    anomaly_score += packet_score * 0.1
    anomaly_score += bps_score * 0.35
    anomaly_score += pps_score * 0.35

    return anomaly_score, (dur_score, volume_score, packet_score, bps_score, pps_score)

def get_window_score_conn(lines: list[str], fft_ruleset: dict):
    """
    Generates a score of a window of transactions by taking the Fourier Transform (FT)
    of the transaction set and comparing it against known benign FT behavior
    """
    
    # (1) prepare the dataframe for the FFT
    cols = [
        "ts",               # [0]
        "uid",              
        "id.orig_h",
        "id.orig_p",        # [3]
        "id.resp_h",
        "id.resp_p",        # [5]
        "proto",
        "service",
        "duration",         # [8]
        "orig_bytes",       # [9]
        "resp_bytes",       # [10]
        "conn_state",
        "local_orig",
        "local_resp",
        "missed_bytes",     # [14]
        "history",          
        "orig_pkts",        # [16]
        "orig_ip_bytes",    # [17]
        "resp_pkts",        # [18]
        "resp_ip_bytes",    # [19]
        "tunnel_parents"
    ]
    
    lines = [line.split(',') for line in lines]
    
    for j in range(len(lines)):
        for i in range(len(lines[j])):
            if lines[j][i] == '-':
                lines[j][i] = 0
            if lines[j][i] == 'T':
                lines[j][i] = 1
            if lines[j][i] == 'F':
                lines[j][i] = 0
            if i in [0, 3, 5, 8, 9, 10, 14, 16, 17, 18, 19]:    # numeric columns
                # print(lines[j][i])
                lines[j][i] = float(lines[j][i])
    
    
    # (2) create the dataframe
    NUMERIC_COLS = [
        'orig_bytes', 'resp_bytes',
        'orig_pkts', 'resp_pkts',
        'duration'
    ]
    window_df = pd.DataFrame(lines, columns=cols)
    for col in NUMERIC_COLS:
        window_df[col] = pd.to_numeric(window_df[col], errors='coerce').fillna(0)
    
    # (3) collect the FT features
    timestamp_fft_feats = fft_timestamps_per_sec_conn(window_df)
    bps_fft_feats = fft_bytes_per_sec_conn(window_df)
    pps_fft_feats = fft_packets_per_sec_conn(window_df)
    conn_fft_feats = fft_conncount_per_sec_conn(window_df)
    
    # (4) [timestamp] compare against ruleset features
    ts_window_ent = timestamp_fft_feats['fft_entropy']
    ts_mean = fft_ruleset['timestamp']['fft_entropy_mean']
    ts_std  = fft_ruleset['timestamp']['fft_entropy_std']
    ts_score = 0.50 if abs(ts_window_ent - ts_mean) > 1 * ts_std else 0
    ts_score = 0.75 if abs(ts_window_ent - ts_mean) > 2 * ts_std else 0
    ts_score = 1.00 if abs(ts_window_ent - ts_mean) > 3 * ts_std else 0
    
    
    # (5) [bytes/sec] compare against ruleset features
    bps_window_ent = bps_fft_feats['fft_entropy']
    bps_mean = fft_ruleset['bps']['fft_entropy_mean']
    bps_std  = fft_ruleset['bps']['fft_entropy_std']
    bps_score = 0.50 if abs(bps_window_ent - bps_mean) > 1 * bps_std else 0
    bps_score = 0.75 if abs(bps_window_ent - bps_mean) > 2 * bps_std else 0
    bps_score = 1.00 if abs(bps_window_ent - bps_mean) > 3 * bps_std else 0
    
    # (6) [packets/sec] compare against ruleset features
    pps_window_ent = pps_fft_feats['fft_entropy']
    pps_mean = fft_ruleset['pps']['fft_entropy_mean']
    pps_std  = fft_ruleset['pps']['fft_entropy_std']
    pps_score = 0.50 if abs(pps_window_ent - pps_mean) > 1 * pps_std else 0
    pps_score = 0.75 if abs(pps_window_ent - pps_mean) > 2 * pps_std else 0
    pps_score = 1.00 if abs(pps_window_ent - pps_mean) > 3 * pps_std else 0
    
    # (7) [conn/sec] compare against ruleset features
    conn_window_ent = conn_fft_feats['fft_entropy']
    conn_mean = fft_ruleset['conn']['fft_entropy_mean']
    conn_std  = fft_ruleset['conn']['fft_entropy_std']
    conn_score = 0.50 if abs(conn_window_ent - conn_mean) > 1 * conn_std else 0
    conn_score = 0.75 if abs(conn_window_ent - conn_mean) > 2 * conn_std else 0
    conn_score = 1.00 if abs(conn_window_ent - conn_mean) > 3 * conn_std else 0
    
    # (8) Calculate anomaly score
    anomaly_score = 0
    anomaly_score += ts_score * 0.2
    anomaly_score += bps_score * 0.2
    anomaly_score += pps_score * 0.3
    anomaly_score += conn_score * 0.3
    
    return anomaly_score, ts_window_ent, bps_window_ent, pps_window_ent, conn_window_ent



def get_rules_score_dns(line: str, ruleset: dict):
    return

def get_window_score_dns(lines: list[str], fft_ruleset: dict):
    return

def get_rules_score_ssl(line: str, ruleset: dict):
    return

def get_window_score_ssl(lines: list[str], fft_ruleset: dict):
    return

def get_rules_score_http(line: str, ruleset: dict):
    return

def get_window_score_http(lines: list[str], fft_ruleset: dict):
    return

# ==== Ruleset Testing ====
def test_single_transaction_scores(from_buf):
    benign_sets = [0, 1, 7, 8, 9, 10, 11]
    malignant_sets = [12, 13, 14, 15, 16, 6]

    for i in range(len(benign_sets)):
        print("************************************************************************************************************")
        print(f"Ruleset: [{conn_paths[benign_sets[i]]}]")
        ruleset = rules_extract.extract_conn_characs(conn_paths[benign_sets[i]], debug=False)

        for j in range(len(benign_sets)):
            print(f"\tBenign Test Set: [{conn_paths[benign_sets[j]]}]")
            scores = []
            anom_scores = []
            with open(conn_paths[benign_sets[j]], 'r') as transactions:
                i = 0
                for transaction in transactions.readlines():
                    if i == 0:
                        i = 1
                        continue
                    
                    transaction = transaction.strip('\n')
                    
                    # print(transaction)
                    score, anom_data = get_rules_score_conn(transaction, ruleset, from_buf=from_buf)
                    scores.append(score)
                    anom_scores.append(anom_data)
                    

            num_anomalies = 0
            for score in scores:
                if score >= 0.5:
                    num_anomalies += 1
                # print(score)

            print(f"\t# flagged transactions = {num_anomalies}")
            FPR = num_anomalies / len(scores)        
            print(f"\tFPR = {FPR} = {(FPR*100):.3f}%")
        
        print()
        for j in range(len(malignant_sets)):
            print(f"\tMalignant Test Set: [{conn_paths[malignant_sets[j]]}]")
            scores = []
            anom_scores = []
            with open(conn_paths[malignant_sets[j]], 'r') as transactions:
                i = 0
                for transaction in transactions.readlines():
                    if i == 0:
                        i = 1
                        continue
                    
                    transaction = transaction.strip('\n')
                    
                    # print(transaction)
                    score, anom_data = get_rules_score_conn(transaction, ruleset, from_buf=from_buf)
                    scores.append(score)
                    anom_scores.append(anom_data)

            num_anomalies = 0
            for score in scores:
                if score >= 0.5:
                    num_anomalies += 1
                # print(score)
            print(f"\t# flagged transactions = {num_anomalies}")
            ACC = num_anomalies / len(scores)   
            print(f"\tAccuracy = {ACC} = {(ACC*100):.3f}%")
        
def test_window_scores(window_size=50, 
                       alpha=0.5, beta=0.3, gamma=0.2, T=0.4, from_buf=False):

    benign_sets = [0, 1, 7, 8, 9, 10, 11]
    malignant_sets = [12, 13, 14, 15, 16, 6]

    for i in range(len(benign_sets)):
        print("************************************************************************************************************")
        print(f"Ruleset: [{conn_paths[benign_sets[i]]}]")

        # Ruleset stays EXACTLY the same as before (transaction-level)
        ruleset = rules_extract.extract_conn_characs(conn_paths[benign_sets[i]], debug=False)

        #
        # =============================
        #   BENIGN TEST SETS
        # =============================
        #
        for j in range(len(benign_sets)):
            print(f"\tBenign Test Set: [{conn_paths[benign_sets[j]]}]")

            # Load all transactions
            with open(conn_paths[benign_sets[j]], 'r') as f:
                lines = f.read().strip().split('\n')[1:]  # skip header

            window_scores = []

            # Sliding window scoring
            for start in range(0, len(lines), window_size):
                window_lines = lines[start:start + window_size]
                if len(window_lines) == 0:
                    continue

                window_score, txn_scores, comps = get_window_score_conn(
                    window_lines, 
                    ruleset,
                    alpha=alpha, beta=beta, gamma=gamma, T=T, from_buf=from_buf
                )
                window_scores.append(window_score)

            # FPR: fraction above threshold
            num_anom = sum(1 for s in window_scores if s >= 0.5)
            FPR = num_anom / len(window_scores)

            print(f"\t# flagged windows = {num_anom}/{len(window_scores)}")
            print(f"\tFPR = {FPR} = {(FPR*100):.3f}%")

        print()

        #
        # =============================
        #   MALIGNANT TEST SETS
        # =============================
        #
        for j in range(len(malignant_sets)):
            print(f"\tMalignant Test Set: [{conn_paths[malignant_sets[j]]}]")

            with open(conn_paths[malignant_sets[j]], 'r') as f:
                lines = f.read().strip().split('\n')[1:]

            window_scores = []

            for start in range(0, len(lines), window_size):
                window_lines = lines[start:start + window_size]
                if len(window_lines) == 0:
                    continue

                window_score, txn_scores, comps = get_window_score_conn(
                    window_lines,
                    ruleset,
                    alpha=alpha, beta=beta, gamma=gamma, T=T
                )
                window_scores.append(window_score)

            # Accuracy: fraction classified as anomalous
            num_hits = sum(1 for s in window_scores if s >= 0.5)
            ACC = num_hits / len(window_scores)

            print(f"\t# flagged windows = {num_hits}/{len(window_scores)}")
            print(f"\tAccuracy = {ACC} = {(ACC*100):.3f}%")

        
# ==== Main Testing Playground ====
# test_single_transaction_scores()


# testing fft scoring for lidar attack 
NUMERIC_COLS = [
    'orig_bytes', 'resp_bytes',
    'orig_pkts', 'resp_pkts',
    'duration'
]

# create the ruleset
t0 = time.time()
ruleset = extract_fft_ruleset_conn()
t1 = time.time()
print(f"Ruleset created in {((t1-t0)/60):.2f} minutes")



for test_path in conn_paths[7:]:
    print(f"Testset: [{test_path}]")
    for window_size in [500, 750, 1000, 1500, 2000, 2500, 2750, 3000]:
        LAST_100_CONN = deque(maxlen=window_size)
        scores = []
        ts_entropies = []
        bps_entropies = []
        pps_entropies = []
        conn_entropies = []
        
        with open(test_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                if line.startswith("ts"):
                    continue
                LAST_100_CONN.append(line)
                if (len(LAST_100_CONN) >= window_size) or (len(lines) < window_size):
                    score, ts_ent, bps_ent, pps_ent, conn_ent = get_window_score_conn(LAST_100_CONN, fft_ruleset=ruleset)
                    scores.append(score)
                    ts_entropies.append(ts_ent)
                    bps_entropies.append(bps_ent)
                    pps_entropies.append(pps_ent)
                    conn_entropies.append(conn_ent)
                else:
                    continue
                

        num_anomalies = 0
        for score in scores:
            if score >= 0.5:
                num_anomalies += 1
                
        print(f"Window Size: {window_size}")
        print(f"Total windows: {len(scores)}")
        print(f"Total alerts: {num_anomalies}")

        if "malignant" in test_path or "attack" in test_path:
            print(f"Accuracy = {((num_anomalies / len(scores)) * 100):.2f}%")
        else:
            print(f"FPR = {((num_anomalies / len(scores)) * 100):.2f}%")

        print(f"Ruleset timestamp (benign) entropy mean: {ruleset['timestamp']['fft_entropy_mean']}")
        print(f"Ruleset bytes/sec (benign) entropy mean: {ruleset['bps']['fft_entropy_mean']}")
        print(f"Ruleset pckts/sec (benign) entropy mean: {ruleset['pps']['fft_entropy_mean']}")
        print(f"Ruleset conns/sec (benign) entropy mean: {ruleset['conn']['fft_entropy_mean']}")
        print(f"Per-window timestamp entropy mean: {np.mean(ts_entropies)}")
        print(f"Per-window bytes/sec entropy mean: {np.mean(bps_entropies)}")
        print(f"Per-window pckts/sec entropy mean: {np.mean(pps_entropies)}")
        print(f"Per-window conns/sec entropy mean: {np.mean(conn_entropies)}")
        print()
    print()
    print()
    

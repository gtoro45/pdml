import rules_extract
from rules_fft import fft_bytes_per_sec_conn, fft_conncount_per_sec_conn, fft_packets_per_sec_conn, fft_timestamps_per_sec_conn, extract_fft_ruleset_conn
# from rules_fft import wavelet_timestamps_per_sec, wavelet_conncount_per_sec, extract_wavelet_ruleset_per_window_size
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

def get_window_score_conn_fft(lines: list[str], fft_ruleset: dict):
    cols = [
        "ts","uid","id.orig_h","id.orig_p",
        "id.resp_h","id.resp_p","proto","service",
        "duration","orig_bytes","resp_bytes","conn_state",
        "local_orig","local_resp","missed_bytes","history",
        "orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes",
        "tunnel_parents"
    ]

    # ================================
    # 1. Parse window lines
    # ================================
    parsed = []
    for L in lines:
        parts = L.split(',')
        row = []
        for i,val in enumerate(parts):
            if val in ['-','F']: val = 0
            elif val == 'T': val = 1
            else:
                if i in [0,3,5,8,9,10,14,16,17,18,19]:  # all numeric cols
                    val = float(val)
            row.append(val)
        parsed.append(row)

    window_df = pd.DataFrame(parsed, columns=cols)

    NUMERIC_COLS = ['orig_bytes','resp_bytes','orig_pkts','resp_pkts','duration']   # numeric cols with potentially missing data
    for col in NUMERIC_COLS:
        window_df[col] = pd.to_numeric(window_df[col], errors="coerce").fillna(0)

    # ================================
    # 2. Compute FFT features
    # ================================
    ts = fft_timestamps_per_sec_conn(window_df)
    bps = fft_bytes_per_sec_conn(window_df)
    pps = fft_packets_per_sec_conn(window_df)
    conn = fft_conncount_per_sec_conn(window_df)

    # ================================
    # 3. Scoring helper
    # ================================
    def score_feature(val, mean, std):
        if std < 1e-9:
            return 0
        z = abs(val - mean) / std
        if z > 3: return 1.0
        if z > 2: return 0.75
        if z > 1: return 0.50
        return 0.0

    ts_score   = score_feature(ts['fft_entropy'],  fft_ruleset['timestamp']['fft_entropy_mean'], fft_ruleset['timestamp']['fft_entropy_std'])
    bps_score  = score_feature(bps['fft_entropy'], fft_ruleset['bps']['fft_entropy_mean'],       fft_ruleset['bps']['fft_entropy_std'])
    pps_score  = score_feature(pps['fft_entropy'], fft_ruleset['pps']['fft_entropy_mean'],       fft_ruleset['pps']['fft_entropy_std'])
    conn_score = score_feature(conn['fft_entropy'],fft_ruleset['conn']['fft_entropy_mean'],      fft_ruleset['conn']['fft_entropy_std'])

    # ================================
    # 4. Weighted anomaly score
    # ================================
    final_score = (
        ts_score   * 0.40 +
        bps_score  * 0.10 +
        pps_score  * 0.25 +
        conn_score * 0.25
    )

    return final_score, ts['fft_entropy'], bps['fft_entropy'], pps['fft_entropy'], conn['fft_entropy']



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

def test_window_scores_fft():
    # testing fft scoring for lidar attack 

    # create the ruleset
    t0 = time.time()
    ruleset = extract_fft_ruleset_conn()    # ruleset and scoring functions must method match (i.e. fft, etc.)
    t1 = time.time()
    print(f"Ruleset created in {((t1-t0)/60):.2f} minutes")

    for test_path in conn_paths[7:]:
        print(f"Testset: [{test_path}]")

        for window_size in [500]:

            WINDOW = deque(maxlen=window_size)
            scores = []
            ts_entropies = []
            bps_entropies = []
            pps_entropies = []
            conn_entropies = []
            window_time_elapsed = []

            stride = window_size // 2
            lines = open(test_path).read().splitlines()
            total = len(lines)

            count_since_eval = 0

            for line in lines:
                if line.startswith("ts"):
                    continue

                WINDOW.append(line)
                count_since_eval += 1

                # Evaluate every STRIDE after window is full
                if len(WINDOW) == window_size and count_since_eval >= stride:
                    score, ts_e, bps_e, pps_e, conn_e = get_window_score_conn_fft(WINDOW, fft_ruleset=ruleset)

                    scores.append(score)
                    ts_entropies.append(ts_e)
                    bps_entropies.append(bps_e)
                    pps_entropies.append(pps_e)
                    conn_entropies.append(conn_e)

                    t0 = float(WINDOW[0].split(',')[0])
                    t1 = float(WINDOW[-1].split(',')[0])
                    window_time_elapsed.append(abs(t1 - t0))

                    count_since_eval = 0

            # final partial window if any
            if len(WINDOW) > 0 and count_since_eval > 0:
                score, ts_e, bps_e, pps_e, conn_e = get_window_score_conn_fft(WINDOW, fft_ruleset=ruleset)

                scores.append(score)
                ts_entropies.append(ts_e)
                bps_entropies.append(bps_e)
                pps_entropies.append(pps_e)
                conn_entropies.append(conn_e)

                t0 = float(WINDOW[0].split(',')[0])
                t1 = float(WINDOW[-1].split(',')[0])
                window_time_elapsed.append(abs(t1 - t0))

            # summary
            anom_score_threshold = 0.5
            alerts = sum(1 for s in scores if s >= anom_score_threshold)

            print(f"Window Size: {window_size}")
            print(f"Total windows: {len(scores)}")
            print(f"Total alerts: {alerts}")

            if any(x in test_path for x in ["malignant","attack"]):
                print(f"Accuracy = {(alerts / len(scores)) * 100:.2f}%")
            else:
                print(f"FPR = {(alerts / len(scores)) * 100:.2f}%")

            print(f"Per-window timestamp entropy mean: {np.mean(ts_entropies):.2f}")
            print(f"Per-window bytes/sec entropy mean: {np.mean(bps_entropies):.2f}")
            print(f"Per-window pckts/sec entropy mean: {np.mean(pps_entropies):.2f}")
            print(f"Per-window conns/sec entropy mean: {np.mean(conn_entropies):.2f}")
            print(f"Window time elapsed: {np.mean(window_time_elapsed):.2f} seconds\n")

        
# ==== Main Testing Playground ====
test_window_scores_fft()
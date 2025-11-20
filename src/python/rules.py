import pandas as pd
import numpy as np
from collections import Counter
import json
import joblib

# ==== Helper Functions ====
def print_stats_list(list: list):
    for item in list:
        print(item)
        print()
        
def print_dict(data: dict):
    try:
        # Use json.dumps for pretty printing, which handles indentation
        # and standard JSON formatting (like double quotes for keys/strings).
        json_output = json.dumps(data, indent=4)
        print(json_output)
    except TypeError as e:
        print(f"Error: Could not serialize dictionary to JSON. {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

# ==== Specify Paths ====
# specify the paths
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
        "../../train_test_data/lidar-attack/csv/nginx-pod/conn.csv"                             # [16]
]
dns_paths = [
        "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_dns.csv",
        "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_dns.csv",
        "../../train_test_data/benign_1_min/nginx-pod/csv files/NGINX_dns.csv",
        "../../train_test_data/benign_sim/csv/dns.csv",                                          # benign
        "../../train_test_data/ddos_sim/csv/dns_malignant1.csv"                                  # malignant
]
ssl_paths = [
        "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_ssl.csv",
        "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_ssl.csv",
        "../../train_test_data/benign_sim/csv/ssl.csv",                                          # benign
        "../../train_test_data/ddos_sim/csv/ssl_malignant1.csv"                                  # malignant
]
http_paths = [
        "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_http.csv",
        "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_http.csv"
]


# ==== Extract rules ====
# extract general characteristics across all files
def extract_general(path):
    df = pd.read_csv(path)
    df = df.sort_values(by="ts")
    
    # (0) handle missing symbols
    df.replace('-', pd.NA, inplace=True)
    df = df.dropna(subset=['ts', 'id.orig_h', 'id.resp_h'])

    
    # (1) get time data between transactions
    ts_diff = df['ts'].diff()[1:]
    ts_avg_diff = ts_diff.mean()
    ts_diff_stdev = ts_diff.std()
    ts_cv = ts_diff_stdev / ts_avg_diff if ts_avg_diff != 0 else 0
    # print(ts_diff)
    print("Avg time between transactions (ms): ", ts_avg_diff * 1000)
    print("Stddev time between transactions (ms): ", ts_diff_stdev * 1000)
    print("stddev/mean", ts_cv, end='\n\n')
    
    # (2) get known addresses and ports for both sender and receiver
    # Build Counters (frequency tables)
    origin_addr_counter = Counter(df['id.orig_h'])
    origin_port_counter = Counter(df['id.orig_p'])
    resp_addr_counter   = Counter(df['id.resp_h'])
    resp_port_counter   = Counter(df['id.resp_p'])

    origin_pair_counter = Counter(zip(df['id.orig_h'], df['id.orig_p']))
    resp_pair_counter   = Counter(zip(df['id.resp_h'], df['id.resp_p']))

    # Convert them into sets of tuples (value, frequency)
    known_origin_addr  = set(origin_addr_counter.items())
    known_origin_ports = set(origin_port_counter.items())
    known_resp_addr    = set(resp_addr_counter.items())
    known_resp_ports   = set(resp_port_counter.items())

    origin_pairs = set(origin_pair_counter.items())
    resp_pairs   = set(resp_pair_counter.items())
    
    # return [
    #     ts_avg_diff,            # float
    #     ts_diff_stdev,          # float
    #     ts_cv,                  # float
    #     known_origin_addr,      # set: (addr, freq) pairs
    #     known_origin_ports,     # set: (port, freq) pairs
    #     known_resp_addr,        # set: (addr, freq) pairs
    #     known_resp_ports,       # set: (port, freq) pairs
    #     origin_pairs,           # set: ((addr, port), freq) pairs
    #     resp_pairs              # set: ((addr, port), freq) pairs
    # ]  
    
    return {
        "ts_avg_diff": ts_avg_diff,                     # float
        "ts_diff_stdev": ts_diff_stdev,                 # float
        "ts_cv": ts_cv,                                 # float
        "known_origin_addr": known_origin_addr,         # set: (addr, freq) pairs
        "known_origin_ports": known_origin_ports,       # set: (port, freq) pairs
        "known_resp_addr": known_resp_addr,             # set: (addr, freq) pairs
        "known_resp_ports": known_resp_ports,           # set: (port, freq) pairs
        "origin_pairs": origin_pairs,                   # set: ((addr, port), freq) pairs
        "resp_pairs": resp_pairs,                       # set: ((addr, port), freq) pairs
    }
    

# ========================
# conn.log field types 
# ========================
# ts                : time          [General]
# uid               : string        [General]
# id.orig_h         : addr          [General]
# id.orig_p         : port          [General]
# id.resp_h         : addr          [General]
# id.resp_p         : port          [General]
# proto             : enum          [.]
# service           : string        [.]
# duration          : interval      [.]
# orig_bytes        : count         [.]
# resp_bytes        : count         [.]
# conn_state        : string        [.]  
# local_orig        : bool          [X]
# local_resp        : bool          [X]
# missed_bytes      : count         [X]
# history           : string        [X]
# orig_pkts         : count         [.]
# orig_ip_bytes     : count         [X] --> proportional to orig_bytes
# resp_pkts         : count         [.]
# resp_ip_bytes     : count         [X] --> proportional to resp_bytes
# tunnel_parents    : set[string]   [X]
# ip_proto          : count         [X]
def extract_conn_characs(conn_path):
    print(f"Dataset: [{conn_path}]")
    # (0) read file, handle missing symbols, get general analysis
    df = pd.read_csv(conn_path)
    df.replace('-', pd.NA, inplace=True)
    df = df.drop(['ts', 'id.orig_h', 'id.resp_h', 'orig_ip_bytes', 'resp_ip_bytes', 'tunnel_parents', 'ip_proto'], errors='ignore')
    
    general = extract_general(conn_path)

    # (1) Protocol and Service analysis
    proto_counts = df['proto'].value_counts(normalize=True).to_dict()       # i.e. {'protocol1' : proportion1, 'protocol2' : proportion2}
    service_counts = df['service'].value_counts(normalize=True).to_dict()   # i.e. {'service1' : proportion1, 'service2' : proportion2}
    print(f"Protocols and relative frequency:")
    print_dict(proto_counts)
    print(f"Services and relative frequency:")
    print_dict(service_counts)
    print()
    
    
    # (2) Duration Statistics
    df['duration'] = pd.to_numeric(df['duration'], errors='coerce')
    dur_mean = df['duration'].mean()
    dur_std = df['duration'].std()
    dur_cv = dur_std / dur_mean if dur_mean != 0 else 0
    print(f"Average transaction duration: {dur_mean}")
    print(f"Average transaction stddev: {dur_std}")
    print(f"stddev/mean: {dur_cv}")
    print()
    
    # (3) Traffic Volume Characteristics
    df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce')
    df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce')
    orig_bytes_total = df['orig_bytes'].sum()
    resp_bytes_total = df['resp_bytes'].sum()
    byte_ratio = orig_bytes_total / (resp_bytes_total + 1e-9) # 1e-9 to avoid div/0 
    print(f"Total origin bytes: {orig_bytes_total} ({(orig_bytes_total / 1_000_000):.5f} MB)")
    print(f"Total resp bytes: {resp_bytes_total} ({(resp_bytes_total / 1_000_000):.5f} MB)")
    print(f"Byte orig/resp ratio: {byte_ratio}")
    print()
    
    bidirectional = df[(df['resp_bytes'] > 0) & (df['orig_bytes'] > 0)]
    orig_only = df[(df['orig_bytes'] > 0) & (df['resp_bytes'] == 0)]
    resp_only = df[(df['resp_bytes'] > 0) & (df['orig_bytes'] == 0)]    

    bidirectional_ratio_mean = (bidirectional['orig_bytes'] / bidirectional['resp_bytes']).mean()
    bidirectional_ratio_std = (bidirectional['orig_bytes'] / bidirectional['resp_bytes']).std()
    orig_only_bytes_mean = orig_only['orig_bytes'].mean()
    orig_only_bytes_std = orig_only['orig_bytes'].std()
    resp_only_bytes_mean = resp_only['resp_bytes'].mean()
    resp_only_bytes_std = resp_only['resp_bytes'].std()
    
    print(f"Bidirectional byte ratio mean: {bidirectional_ratio_mean}")
    print(f"Bidirectional byte ratio std: {bidirectional_ratio_std}")
    print(f"Orig-only bytes mean: {orig_only_bytes_mean} ({(orig_only_bytes_mean / 1_000_000):.5f} MB)")
    print(f"Orig-only bytes std: {orig_only_bytes_std} ({(orig_only_bytes_std / 1_000_000):.5f} MB)")
    print(f"Resp-only bytes mean: {resp_only_bytes_mean} ({(resp_only_bytes_mean / 1_000_000):.5f} MB)")
    print(f"Resp-only bytes std: {resp_only_bytes_std} ({(resp_only_bytes_std / 1_000_000):.5f} MB)")
    print()
    
    # (4) Packet-Level Behavior
    df['orig_pkts'] = pd.to_numeric(df['orig_pkts'], errors='coerce')
    df['resp_pkts'] = pd.to_numeric(df['resp_pkts'], errors='coerce')
    orig_pkts_total = df['orig_pkts'].sum()
    resp_pkts_total = df['resp_pkts'].sum()
    pkts_ratio = orig_pkts_total / (resp_pkts_total + 1e-9) # 1e-9 to avoid div/0
    print(f"Total origin pkts: {orig_pkts_total}")
    print(f"Total resp pkts: {resp_pkts_total}")
    print(f"Pkt orig/resp ratio: {pkts_ratio}")
    print()
    
    bidirectional_pkts = df[(df['resp_pkts'] > 0) & (df['orig_pkts'] > 0)]
    orig_only_pkts = df[(df['orig_pkts'] > 0) & (df['resp_pkts'] == 0)]
    resp_only_pkts = df[(df['resp_pkts'] > 0) & (df['orig_pkts'] == 0)] 

    pkts_ratio_mean = (bidirectional_pkts['orig_pkts'] / bidirectional_pkts['resp_pkts']).mean()
    pkts_ratio_std = (bidirectional_pkts['orig_pkts'] / bidirectional_pkts['resp_pkts']).std()
    orig_only_pkts_mean = orig_only_pkts['orig_pkts'].mean()
    orig_only_pkts_std = orig_only_pkts['orig_pkts'].std()
    resp_only_pkts_mean = resp_only_pkts['resp_pkts'].mean()
    resp_only_pkts_std = resp_only_pkts['resp_pkts'].std()
    
    print(f"Bidirectional pkt ratio mean: {pkts_ratio_mean}")
    print(f"Bidirectional pkt ratio std: {pkts_ratio_std}")
    print(f"Orig-only pkt mean: {orig_only_pkts_mean}")
    print(f"Orig-only pkt std: {orig_only_pkts_std}")
    print(f"Resp-only pkt mean: {resp_only_pkts_mean}")
    print(f"Resp-only pkt std: {resp_only_pkts_std}")
    print()
    
    # (5) Connection State Distribution
    state_counts = df['conn_state'].value_counts(normalize=True).to_dict()
    # state_entropy = -sum(p * np.log2(p) for p in state_counts.values())
    print(f"Connection states and relative frequency:")
    print_dict(state_counts)
    # print(f"State entropy (bits): {state_entropy}")
    print()
    
    
    # (6) format return dictionary and terminate function
    return {
        'general' : general,
        
        'proto_service' : {
            "proto_counts": proto_counts,       # (1) : dict    {'protocol1' : proportion1, 'protocol2' : proportion2}
            "service_counts": service_counts    # (1) : dict    {'service1' : proportion1, 'service2' : proportion2}
        },
        
        'duration' : {
            "mean": dur_mean,                   # (2) : float
            "std": dur_std,                     # (2) : float
            "cv": dur_cv                        # (2) : float
        },
        
        'bytes' : {
            "orig_total": orig_bytes_total,                     # (3) : float
            "resp_total": resp_bytes_total,                     # (3) : float
            "ratio": byte_ratio,                                # (3) : float
            "bidirectional_mean": bidirectional_ratio_mean,     # (3) : float
            "bidirectional_std": bidirectional_ratio_std,       # (3) : float
            "orig_only_mean": orig_only_bytes_mean,             # (3) : float
            "orig_only_std": orig_only_bytes_std,               # (3) : float
            "resp_only_mean": resp_only_bytes_mean,             # (3) : float
            "resp_only_std": resp_only_bytes_std                # (3) : float
        },
        
        'packets' : {
            "orig_total": orig_pkts_total,              # (4) : float
            "resp_total": resp_pkts_total,              # (4) : float
            "ratio": pkts_ratio,                        # (4) : float
            "bidirectional_mean": pkts_ratio_mean,      # (4) : float
            "bidirectional_std": pkts_ratio_std,        # (4) : float
            "orig_only_mean": orig_only_pkts_mean,      # (4) : float
            "orig_only_std": orig_only_pkts_std,        # (4) : float
            "resp_only_mean": resp_only_pkts_mean,      # (4) : float
            "resp_only_std": resp_only_pkts_std         # (4) : float
        },
        
        'states' : {
            "state_counts": state_counts                # (5) : dict    {'state1' : proportion1, 'state2' : proportion2}
        }
    }


# ========================
# dns.log field types
# ========================
# ts            : time                  [General]
# uid           : string                [General]
# id.orig_h     : addr                  [General]
# id.orig_p     : port                  [General]
# id.resp_h     : addr                  [General]
# id.resp_p     : port                  [General]
# proto         : enum                  [.]
# trans_id      : count                 [X]
# rtt           : interval              [.]
# query         : string                [.]
# qclass        : count                 [X]
# qclass_name   : string                [.]
# qtype         : count                 [X]
# qtype_name    : string                [.]
# rcode         : count                 [X]
# rcode_name    : string                [.]
# AA            : bool                  [X]
# TC            : bool                  [X]
# RD            : bool                  [X]
# RA            : bool                  [X]
# Z             : count                 [X]
# answers       : vector[string]        [X]
# TTLs          : vector[interval]      [X]
# rejected      : bool                  [.]
def extract_dns_characs(dns_path):
    print(f"[{dns_path}]")
    # (0) read file, handle missing symbols, get general analysis
    df = pd.read_csv(dns_path)
    df.replace('-', pd.NA, inplace=True)
    df = df.drop(['ts', 'id.orig_h', 'id.resp_h', 'trans_id', 'qclass', 'AA', 'TC', 'RD', 'RA', 'Z', 'answers', 'TTLs'], errors='ignore')
    general = extract_general(dns_path)

    # (1) Protocol analysis
    proto_counts = df['proto'].value_counts(normalize=True).to_dict()       # i.e. {'protocol1' : proportion1, 'protocol2' : proportion2}
    print(f"Protocols and relative frequency:")
    print_dict(proto_counts)
    print()
    
    # (2) rtt (round-trip time) Statistics
    df['rtt'] = pd.to_numeric(df['rtt'], errors='coerce')
    rtt_mean = df['rtt'].mean()
    rtt_std = df['rtt'].std()
    rtt_cv = rtt_std / rtt_mean if rtt_mean != 0 else 0
    print(f"Average transaction rtt: {rtt_mean}")
    print(f"Average transaction stddev: {rtt_std}")
    print(f"stddev/mean: {rtt_cv}")
    print()

    # (3) Query Information (Extract Known Queries)
    query_counts = df['query'].value_counts(normalize=True).to_dict()       # i.e. {'query1' : proportion1, 'query2' : proportion2} (set-like)
    print("Queries and Relative Frequency")
    print_dict(query_counts)
    print()

    # (4) qclass, qtype, rcode names and frequencies
    qclass_name_counts = df['qclass_name'].value_counts(normalize=True).to_dict()   # i.e. {'query1' : proportion1, 'query2' : proportion2} (set-like)
    qtype_name_counts = df['qtype_name'].value_counts(normalize=True).to_dict()     # i.e. {'query1' : proportion1, 'query2' : proportion2} (set-like)
    rcode_name_counts = df['rcode_name'].value_counts(normalize=True).to_dict()     # i.e. {'query1' : proportion1, 'query2' : proportion2} (set-like)
    print("DNS qclass_name(s) and relative frequency:")
    print_dict(qclass_name_counts)
    print("DNS qtype_name(s) and relative frequency:")
    print_dict(qtype_name_counts)
    print("DNS rcode_name(s) and relative frequency:")
    print_dict(rcode_name_counts)
    print()

    # (5) Count % Rejections
    df['rejected'] = df['rejected'].map({'T' : True, 'F' : False, pd.NA : 0})
    num_rejections = len(df[df['rejected'] == True])
    num_transactions = len(df['rejected'].dropna())
    rejection_ratio = num_rejections / num_transactions
    print(f"Number of rejections: {num_rejections}")
    print(f"Number of transactions: {num_transactions}")
    print(f"Rejection ratio: {rejection_ratio}")
    

    # return general stats + specific stats
    return {
        'general': general,

        'protocol': {
            'proto_counts': proto_counts        # dict: {'proto1' : proportion1, 'proto2' : proportion2} (set-like)
        },

        'timing': {
            'rtt_mean': rtt_mean,               # float
            'rtt_std': rtt_std,                 # float
            'rtt_cv': rtt_cv                    # float
        },

        'queries': {
            'query_counts': query_counts        # dict: {'query1' : proportion1, 'query2' : proportion2} (set-like)
        },

        'categories': {
            'qclass_name_counts': qclass_name_counts,   # dict
            'qtype_name_counts': qtype_name_counts,     # dict
            'rcode_name_counts': rcode_name_counts      # dict
        },

        'rejections': {
            'num_rejections': num_rejections,           # int
            'num_transactions': num_transactions,       # int
            'rejection_ratio': rejection_ratio          # float
        }
    }


# ========================
# ssl.log field types
# ========================
# ts                     : time             [General]
# uid                    : string           [General]
# id.orig_h              : addr             [General]
# id.orig_p              : port             [General]
# id.resp_h              : addr             [General]
# id.resp_p              : port             [General]
# version                : string           [.]
# cipher                 : string           [.]
# curve                  : string           [.]
# server_name            : string           [.]
# resumed                : bool             [X]
# last_alert             : string           [X]
# next_protocol          : string           [X]
# established            : bool             [.]
# ssl_history            : string           [X]
# cert_chain_fps         : vector[string]   [X]
# client_cert_chain_fps  : vector[string]   [X]
# sni_matches_cert       : bool             [X]
def extract_ssl_characs(ssl_path):
    print(f"[{ssl_path}]")
    # (0) read file, handle missing symbols, get general analysis
    df = pd.read_csv(ssl_path)
    df.replace('-', pd.NA, inplace=True)
    df = df.drop(['ts', 'id.orig_h', 'id.resp_h', 'sni_matches_cert', 'resumed', 'last_alert', 'next_protocol', 'ssl_history'], errors='ignore')
    general = extract_general(ssl_path)

    # (1) Version, Cipher, and Curve Analysis
    version_counts = df['version'].value_counts(normalize=True).to_dict() 
    cipher_counts = df['cipher'].value_counts(normalize=True).to_dict() 
    curve_counts = df['curve'].value_counts(normalize=True).to_dict() 
    print("SSL Version(s) and relative frequency:")
    print_dict(version_counts)
    print("SSL Cipher(s) and relative frequency")
    print_dict(cipher_counts)
    print("SSL Curve(s) and relative frequency:")
    print_dict(curve_counts)
    print()
    
    # (2) Known Servers
    known_servers = df['server_name'].value_counts(normalize=True).to_dict()
    print("SSL Known Server(s) and relative frequency:")
    print_dict(known_servers)

    # (3) Count Esablished Transactions
    df['established'] = df['established'].map({'T' : True, 'F' : False, pd.NA : 0})
    num_established = len(df[df['established'] == True])
    num_transactions = len(df['established'].dropna())
    established_ratio = num_established / num_transactions
    print(f"Number of established transactions: {num_established}")
    print(f"Number of transactions: {num_transactions}")
    print(f"Rejection ratio: {established_ratio}")

    # return general stats + specific stats
    return {
        'general' : general,

        'ssl_characs' : {
            'version_counts' : version_counts,
            'cipher_counts' : cipher_counts,
            'curve_counts' : curve_counts
        },

        'servers' : {
            'known_servers' : known_servers
        },

        'establishment_characs' : {
            'num_established_transactions' : num_established,
            'num_transactions' : num_transactions,
            'established_ratio' : established_ratio
        }
    }

# ========================
# http.log field types
# ========================
# ts                 : time             [General]
# uid                : string           [General]
# id.orig_h          : addr             [General]
# id.orig_p          : port             [General]
# id.resp_h          : addr             [General]
# id.resp_p          : port             [General]
# trans_depth        : count            [.]
# method             : string           [/]
# host               : string           [.]
# uri                : string           [.]
# referrer           : string           [X]        
# version            : string           [X]
# user_agent         : string           [.]
# origin             : string           
# request_body_len   : count
# response_body_len  : count
# status_code        : count
# status_msg         : string           
# info_code          : count
# info_msg           : string
# tags               : set[enum]
# username           : string           
# password           : string           
# proxied            : set[string]
# orig_fuids         : vector[string]   [X]
# orig_filenames     : vector[string]   [X]
# orig_mime_types    : vector[string]   [X]
# resp_fuids         : vector[string]   [X]
# resp_filenames     : vector[string]   [X]
# resp_mime_types    : vector[string]   [X]
def extract_http_characs(http_path):
    print(f"[{http_path}]")
    # (0) read file, handle missing symbols, get general analysis
    df = pd.read_csv(http_path)
    df.replace('-', pd.NA, inplace=True)
    df = df.drop(['ts', 'id.orig_h', 'id.resp_h', 'referrer', 'version'], errors='ignore')
    general = extract_general(http_path)
    
    # (1) Transaction Depth Metrics
    trans_depth_avg = df['trans_depth'].dropna().mean()
    trans_depth_std = df['trans_depth'].dropna().std()
    trans_depth_cv = trans_depth_std / trans_depth_avg
    print(f"HTTP average transaction depth: {trans_depth_avg}")
    print(f"HTTP transaction depth stddev: {trans_depth_std}")
    print(f"stddev/avg: {trans_depth_cv}")
    
    # (2) Method Metrics
    # this will be more for scoring, add later if needed 'method'
    
    # (3) Known Hosts, URIs, and User Agents
    known_hosts = df['host'].dropna().value_counts(normalize=True).to_dict()
    known_uris = df['uri'].dropna().value_counts(normalize=True).to_dict()
    known_agents = df['user_agent'].dropna().value_counts(normalize=True).to_dict()
    print("HTTP known hosts: ")
    print_dict(known_hosts)
    print("HTTP known URIs: ")
    print_dict(known_uris)
    print("HTTP known user agents: ")
    print_dict(known_agents)
    
    # (4) Request/Response Body Lengths [ = size(data transferred from server)]
    
    
    # return general stats + specific stats
    return {
        'general' : general
    }


# ==== Calculate a rules score based on the log type for a SINGLE LINE ====
def get_rules_score_conn(line: str, ruleset: list):
    return

def get_rules_score_dns(line: str, ruleset: list):
    return

def get_rules_score_ssl(line: str, ruleset: list):
    return

def get_rules_score_http(line: str, ruleset: list):
    return



# === Testing and Saving ====
# CONN
print("==============================================================================================================")
# extract_conn_characs(conn_paths[0])
# print("************************************************************************************************************")
# extract_conn_characs(conn_paths[1])
# print("************************************************************************************************************")
# extract_conn_characs(conn_paths[2])
# print("************************************************************************************************************")
# extract_conn_characs(conn_paths[3])
# print("************************************************************************************************************")
# extract_conn_characs(conn_paths[4])
# print("************************************************************************************************************")
# extract_conn_characs(conn_paths[5])
# print("************************************************************************************************************")
# extract_conn_characs(conn_paths[6])
# print("************************************************************************************************************")

# new benign data
print("======== BENIGN KUBERNETES CLUSTER TRAFFIC ========")
extract_conn_characs(conn_paths[7])
print("************************************************************************************************************")
extract_conn_characs(conn_paths[8])
print("************************************************************************************************************")
extract_conn_characs(conn_paths[9])
print("************************************************************************************************************")
extract_conn_characs(conn_paths[10])
print("************************************************************************************************************")
extract_conn_characs(conn_paths[11])
print()

# attack data
print("======== MALIGNANT KUBERNETES CLUSTER TRAFFIC ========")
print("************************************************************************************************************")
extract_conn_characs(conn_paths[12])
print("************************************************************************************************************")
extract_conn_characs(conn_paths[13])
print("************************************************************************************************************")
extract_conn_characs(conn_paths[14])
print("************************************************************************************************************")
print("<<<< THIS IS THE POD BEING ATTACKED >>>>")
extract_conn_characs(conn_paths[15])
print("************************************************************************************************************")
extract_conn_characs(conn_paths[16])

# DNS
# print("==============================================================================================================")
# extract_dns_characs(dns_paths[0])
# print("************************************************************************************************************")
# extract_dns_characs(dns_paths[1])
# print("************************************************************************************************************")
# extract_dns_characs(dns_paths[2])
# print("************************************************************************************************************")
# extract_dns_characs(dns_paths[3])
# print("************************************************************************************************************")
# extract_dns_characs(dns_paths[4])
# print("************************************************************************************************************")

# SSL
# print("==============================================================================================================")
# extract_ssl_characs(ssl_paths[0])
# print("************************************************************************************************************")
# extract_ssl_characs(ssl_paths[1])
# print("************************************************************************************************************")
# extract_ssl_characs(ssl_paths[2])
# print("************************************************************************************************************")
# extract_ssl_characs(ssl_paths[3])
# print("************************************************************************************************************")

# HTTP
# print("==============================================================================================================")
# extract_http_characs(http_paths[0])
# print("************************************************************************************************************")
# extract_http_characs(http_paths[1])
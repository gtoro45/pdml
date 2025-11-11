import pandas as pd
from collections import Counter
import joblib

# ==== Helper Functions ====
def print_stats_list(list):
    for item in list:
        print(item)
        print()

# ==== Specify Paths ====
# specify the paths
conn_paths = [
    "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_conn.csv",
    "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_conn.csv",
    "../../train_test_data/benign_1_min/cam-pod/csv files/camera_conn.csv",
    "../../train_test_data/benign_1_min/lidar-pod/csv files/lidar_conn.csv",
    "../../train_test_data/benign_1_min/nginx-pod/csv files/NGINX_conn.csv",
    "../../train_test_data/benign_sim/csv/conn.csv",                                          # benign
    "../../train_test_data/ddos_sim/csv/conn_malignant1.csv"                                  # malignant
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
    ts_cv = ts_diff_stdev / ts_avg_diff
    # print(ts_diff)
    # print("Average Diff: ", ts_avg_diff)
    # print("Std Deviation: ", ts_diff_stdev)
    # print("Coefficient of Variation", ts_cv, end='\n\n')
    
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

    
    
    return [
        ts_avg_diff,            # float
        ts_diff_stdev,          # float
        ts_cv,                  # float
        known_origin_addr,      # set: (addr, freq) pairs
        known_origin_ports,     # set: (port, freq) pairs
        known_resp_addr,        # set: (addr, freq) pairs
        known_resp_ports,       # set: (port, freq) pairs
        origin_pairs,           # set: ((addr, port), freq) pairs
        resp_pairs              # set: ((addr, port), freq) pairs
    ]

def extract_conn_characs(conn_path):
    
    # return general stats + specific stats
    return extract_general(conn_path) + [None]

def extract_dns_characs(dns_path):
    
    # return general stats + specific stats
    return extract_general(dns_path) + [None]

def extract_ssl_characs(ssl_path):
    
    # return general stats + specific stats
    return extract_general(ssl_path) + [None]

def extract_http_characs(http_path):
    
    # return general stats + specific stats
    return extract_general(http_path) + [None]


# ==== Calculate a rules score based on the log type ====
def get_rules_score_conn(line: str, ruleset: list):
    return

def get_rules_score_dns(line: str, ruleset: list):
    return

def get_rules_score_ssl(line: str, ruleset: list):
    return

def get_rules_score_http(line: str, ruleset: list):
    return



# === Testing and Saving ====
# print_stats_list(extract_conn_characs(conn_paths[0]))
# print_stats_list(extract_conn_characs(conn_paths[1]))
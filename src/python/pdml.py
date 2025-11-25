import encoding
import pdml.src.python.rules_scoring as rules_scoring
import joblib
import argparse
import os
from time import sleep
from collections import deque

# ******************************************************
# THIS CODE IS RAN PER NODE/CHILD IN THE KUBERNETES 
# CLUSTER, AND THEREFORE TAKES THAT IN AS INPUT FOR THE
# MODELS AND RULES TO LOAD PROPERLY FROM CORRECT PATHS
# ******************************************************
parser = argparse.ArgumentParser(description='Process logs with specified node/child (module)')
parser.add_argument('--module', type=str, required=True, help='node/child to process data from')
args = parser.parse_args()
module = args.module

BUF_FILE = f"../../buf/{module}.csv"
DATA_PREFIX = f"./feature_sets/{module}/"

available_data = {
    "node1" : ["conn"], #, "dns", "http", "ssl"],
    "node2" : ["conn"], #, "dns", "http", "ssl"],
    "cam"   : ["conn"],
    "lidar" : ["conn"],
    "nginx" : ["conn"], # "dns"]
}
if module not in available_data:
    raise ValueError(f"Unknown module '{module}'. Must be one of: {', '.join(available_data.keys())}")


# ==== Paths to Models and Rules, and CSV Buffer for each log type ====
CONN_DATA_PATHS = []
DNS_DATA_PATHS = []
SSL_DATA_PATHS = []
HTTP_DATA_PATHS = []
for log_type in ["conn", "dns", "http", "ssl"]:
    if log_type in available_data[module]:
        model_path = os.path.join(DATA_PREFIX, f"{log_type}_model.joblib")
        rule_path  = os.path.join(DATA_PREFIX, f"{log_type}_rules.joblib")
        fft_path   = os.path.join(DATA_PREFIX, f"{log_type}_fft.joblib") 

        if log_type == "conn":
            CONN_DATA_PATHS = [model_path, rule_path]
        elif log_type == "dns":
            DNS_DATA_PATHS = [model_path, rule_path]
        elif log_type == "http":
            HTTP_DATA_PATHS = [rule_path]
        elif log_type == "ssl":
            SSL_DATA_PATHS = [model_path, rule_path]
    else:
        if log_type == "conn":
            CONN_DATA_PATHS = [None, None]
        elif log_type == "dns":
            DNS_DATA_PATHS = [None, None]
        elif log_type == "http":
            HTTP_DATA_PATHS = [None, None]
        elif log_type == "ssl":
            SSL_DATA_PATHS = [None, None]

print(f"\nLoaded module: {module}")     # DEBUG
print(f"BUF_FILE: {BUF_FILE}")          # DEBUG
print("conn ->", CONN_DATA_PATHS)       # DEBUG
print("dns  ->", DNS_DATA_PATHS)        # DEBUG
print("http ->", HTTP_DATA_PATHS)       # DEBUG
print("ssl  ->", SSL_DATA_PATHS)        # DEBUG

# ==== Instantiate the Models, Rules, and Buffers ====
# rules
conn_rule_set = joblib.load(CONN_DATA_PATHS[1]) if None not in CONN_DATA_PATHS else None
dns_rule_set = joblib.load(DNS_DATA_PATHS[1]) if None not in DNS_DATA_PATHS else None
ssl_rule_set = joblib.load(SSL_DATA_PATHS[1]) if None not in SSL_DATA_PATHS else None
http_rule_set = joblib.load(HTTP_DATA_PATHS[0]) if None not in HTTP_DATA_PATHS else None

# # models
conn_model = joblib.load(CONN_DATA_PATHS[0]) if None not in CONN_DATA_PATHS else None
dns_model = joblib.load(DNS_DATA_PATHS[0]) if None not in DNS_DATA_PATHS else None
ssl_model = joblib.load(SSL_DATA_PATHS[0]) if None not in SSL_DATA_PATHS else None

# buffers (priority queues for broader statistical analysis, sorted by timestamp)
conn_count = 0
dns_count = 0
ssl_count = 0
http_count = 0

LAST_100_CONN = deque(maxlen=100)
LAST_100_DNS = deque(maxlen=100)
LAST_100_SSL = deque(maxlen=100)
LAST_100_HTTP = deque(maxlen=100)

def place_in_window(line: str):
    # Use .append() to add the new element to the right end
    # If the deque is full (100 elements), the oldest element is automatically removed.
    if 'CONN' in line:
        LAST_100_CONN.append(line[5:])  # remove 'CONN,' from front of line
    elif 'DNS' in line:
        LAST_100_DNS.append(line[4:])   # remove 'DNS,' from front of line
    elif 'SSL' in line:
        LAST_100_SSL.append(line[4:])   # remove 'SSL,' from front of line
    elif 'HTTP' in line:        
        LAST_100_HTTP.append(line[5:])  # remove 'HTTP,' from front of line
        

# ==== Retreival Functions ====
def get_rules_score(line: str):
    if 'CONN' in line:
        return rules_scoring.get_rules_score_conn(line, conn_rule_set, from_buf=True)
    if 'DNS' in line:
        return rules_scoring.get_rules_score_dns(line, dns_rule_set, from_buf=True)
    if 'SSL' in line:
        return rules_scoring.get_rules_score_ssl(line, ssl_rule_set, from_buf=True)
    if 'HTTP' in line:
        return rules_scoring.get_rules_score_http(line, http_rule_set, from_buf=True)
    return -1

def get_window_score(line: str):
    if 'CONN' in line:
        return rules_scoring.get_window_score_conn(LAST_100_CONN)
    if 'DNS' in line:
        return rules_scoring.get_window_score_dns(LAST_100_DNS)
    if 'SSL' in line:
        return rules_scoring.get_window_score_ssl(LAST_100_SSL)
    if 'HTTP' in line:
        return rules_scoring.get_window_score_http(LAST_100_HTTP)
    return -1


def get_model_score(line: str):
    # TODO
    return -1

# ==== Main Function ====
def main():
    # Dummy loop for formatting, will be changed to watcher function in watcher.py
    with open(BUF_FILE, 'r') as file:    
        file.seek(0, os.SEEK_END)
        transaction_cycles = 0
        while True:
            # (0) read the latest line, place into window
            line = file.readline()
            if not line:
                sleep(0.5)
                continue
            line = line.strip()
            if not line: continue
            transaction_cycles += 1
            
            # ***************** SINGLE TRANSACTION TESTS *****************
            # (1) acquire the rules score (simple rules, known ips, etc.)   --> leave for 404/discard: this is NOT great for random traffic 
            
            # (2) acquire the model score (isolation forest outlier)        --> leave for 404/discard: maybe, depends if forest model is capable enough
            
            # (3) calculate the anomaly score (rules + model score)         --> leave for 404/discard
            
            # (4) API post request (anomalous transaction)                  --> leave for 404/discard
            # ************************************************************
            
            # ******************* SLIDING WINDOW TESTS *******************
            # (5) Add line to the corresponding window (prev. 100 transactions)
            place_in_window(line)
            
            # (6) FFT the window against benign FFT and calculate window anomaly score 
            #     only check the window corresponding to the most recent (current) transaction     
            window_score = get_window_score(line)
            
            # (7) API post request (anomalous patterns)                     
            
            # ************************************************************
            
            sleep(1)

    return 0   

main()
    
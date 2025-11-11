import encoding
import rules
import joblib
import argparse
import os
from time import sleep


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
DATA_PREFIX = f"./models/{module}/"

available_data = {
    "node1" : ["conn", "dns", "http", "ssl"],
    "node2" : ["conn", "dns", "http", "ssl"],
    "cam"   : ["conn"],
    "lidar" : ["conn"],
    "nginx" : ["conn", "dns"]
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

# buffers (for rate checking)
conn_count = 0
dns_count = 0
ssl_count = 0
http_count = 0
last_100_conn = []
last_100_dns = []
last_100_ssl = []
last_100_http = []

# ==== Retreival Functions ====
def get_rules_score(line: str):
    if 'CONN' in line:
        return rules.get_rules_score_conn(line, conn_rule_set)
    if 'DNS' in line:
        return rules.get_rules_score_dns(line, dns_rule_set)
    if 'SSL' in line:
        return rules.get_rules_score_ssl(line, ssl_rule_set)
    if 'HTTP' in line:
        return rules.get_rules_score_http(line, http_rule_set)
    return -1

def get_model_score(line: str):
    # TODO
    return -1

# ==== Main Function ====
def main():
    # Dummy loop for formatting, will be changed to watcher function in watcher.py
    with open(BUF_FILE, 'r') as file:    
        file.seek(0, os.SEEK_END)
        
        while True:
            # (0) read the latest line
            line = file.readline()
            if not line:
                sleep(0.5)
                continue
            line = line.strip()
            if not line: continue
            
            # (1) acquire the rules score
            rules_score = get_rules_score(line)
            
            # (2) acquire the model score
            
            # (3) calculate the anomaly score
            
            # (4) API post request
            
            sleep(1)

    return 0   

main()
    
import joblib
import argparse
import os
from time import sleep
from collections import deque
import pandas as pd
import numpy as np
import xgb
import copy

# ******************************************************
# THIS CODE IS RAN PER NODE/CHILD IN THE KUBERNETES 
# CLUSTER, AND THEREFORE TAKES THAT IN AS INPUT FOR THE
# MODELS AND RULES TO LOAD PROPERLY FROM CORRECT PATHS
# ******************************************************
# parser = argparse.ArgumentParser(description='Process logs with specified node/child (module)')
# parser.add_argument('--module', type=str, required=True, help='node/child to process data from')
# args = parser.parse_args()
# module = args.module

# BUF_FILE = f"../../buf/{module}.csv"

# === LOAD TRAINING SCHEMA ===
# We must load a CSV used in training because THAT defines column order + names.
TRAIN_SCHEMA = pd.read_csv(
    "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",
    nrows=1
).columns.tolist()

# The model was trained on whatever numeric columns existed in CSVs
DUMMY_DF = pd.read_csv("../../train_test_data/new-benign_10_min/csv/child1/conn.csv", nrows=50)
TRAIN_NUMERIC_COLS = DUMMY_DF.select_dtypes(include=[np.number]).columns.tolist()

BUF_FILE = "../../train_test_data/lidar-attack/csv/child2/conn.csv"
BUF_FILE = "../../train_test_data/new-benign_10_min/csv/child2/conn.csv"
BUF_FILE = "../../train_test_data/combined_benign_conn_BNB.csv"


# DATA_PREFIX = f"./feature_sets/{module}/"

# available_data = {
#     "node1" : ["conn"], #, "dns", "http", "ssl"],
#     "node2" : ["conn"], #, "dns", "http", "ssl"],
#     "cam"   : ["conn"],
#     "lidar" : ["conn"],
#     "nginx" : ["conn"], # "dns"]
# }
# if module not in available_data:
#     raise ValueError(f"Unknown module '{module}'. Must be one of: {', '.join(available_data.keys())}")


# # ==== Paths to Models and Rules, and CSV Buffer for each log type ====
# CONN_DATA_PATHS = []
# DNS_DATA_PATHS = []
# SSL_DATA_PATHS = []
# HTTP_DATA_PATHS = []
# for log_type in ["conn", "dns", "http", "ssl"]:
#     if log_type in available_data[module]:
#         model_path = os.path.join(DATA_PREFIX, f"{log_type}_model.joblib")
#         rule_path  = os.path.join(DATA_PREFIX, f"{log_type}_rules.joblib")
#         fft_path   = os.path.join(DATA_PREFIX, f"{log_type}_fft.joblib") 

#         if log_type == "conn":
#             CONN_DATA_PATHS = [model_path, rule_path]
#         elif log_type == "dns":
#             DNS_DATA_PATHS = [model_path, rule_path]
#         elif log_type == "http":
#             HTTP_DATA_PATHS = [rule_path]
#         elif log_type == "ssl":
#             SSL_DATA_PATHS = [model_path, rule_path]
#     else:
#         if log_type == "conn":
#             CONN_DATA_PATHS = [None, None]
#         elif log_type == "dns":
#             DNS_DATA_PATHS = [None, None]
#         elif log_type == "http":
#             HTTP_DATA_PATHS = [None, None]
#         elif log_type == "ssl":
#             SSL_DATA_PATHS = [None, None]

# print(f"\nLoaded module: {module}")     # DEBUG
# print(f"BUF_FILE: {BUF_FILE}")          # DEBUG
# print("conn ->", CONN_DATA_PATHS)       # DEBUG
# print("dns  ->", DNS_DATA_PATHS)        # DEBUG
# print("http ->", HTTP_DATA_PATHS)       # DEBUG
# print("ssl  ->", SSL_DATA_PATHS)        # DEBUG

# ==== Instantiate the Models, Rules, and Buffers ====
# rules
# conn_rule_set = joblib.load(CONN_DATA_PATHS[1]) if None not in CONN_DATA_PATHS else None
# dns_rule_set = joblib.load(DNS_DATA_PATHS[1]) if None not in DNS_DATA_PATHS else None
# ssl_rule_set = joblib.load(SSL_DATA_PATHS[1]) if None not in SSL_DATA_PATHS else None
# http_rule_set = joblib.load(HTTP_DATA_PATHS[0]) if None not in HTTP_DATA_PATHS else None

# # models
conn_model = joblib.load("./models/conn_model.joblib")
# dns_model = joblib.load(DNS_DATA_PATHS[0]) if None not in DNS_DATA_PATHS else None
# ssl_model = joblib.load(SSL_DATA_PATHS[0]) if None not in SSL_DATA_PATHS else None

# buffers (priority queues for broader statistical analysis, sorted by timestamp)
conn_count = 0
# dns_count = 0
# ssl_count = 0
# http_count = 0

WINDOW_SIZE = 200

CONN_WINDOW = deque(maxlen=WINDOW_SIZE)
DNS_WINDOW = deque(maxlen=WINDOW_SIZE)
SSL_WINDOW = deque(maxlen=WINDOW_SIZE)
HTTP_WINDOW = deque(maxlen=WINDOW_SIZE)

def place_in_window(line: str):
    if not line:
        return

    parts = line.split(',')
    if len(parts) != len(TRAIN_SCHEMA):
        return   # schema mismatch

    # Create 1-row df identical to training layout
    row = pd.DataFrame([parts], columns=TRAIN_SCHEMA)

    # Convert all numeric columns
    for col in TRAIN_NUMERIC_COLS:
        row[col] = pd.to_numeric(row[col], errors="coerce").fillna(0)

    # Append entire dataframe row (not numpy array!)
    CONN_WINDOW.append(row)

# ==== Retreival Functions ====
def get_window_score():
    if len(CONN_WINDOW) < WINDOW_SIZE:
        return 0, 0.0

    # Concatenate window into a dataframe exactly like xgb.py
    window_df = pd.concat(list(CONN_WINDOW), ignore_index=True)

    # Extract window-level feature vector (same shape as training)
    features_df = xgb.window_features(window_df, WINDOW_SIZE)

    # xgb.window_features() returns many windows; we want the first/only one
    features = features_df.iloc[[0]]

    pred = conn_model.predict(features)[0]
    score = conn_model.predict_proba(features)[0, 1]

    return pred, score


# ==== Main Function ====
def main():
    # Dummy loop for formatting, will be changed to watcher function in watcher.py
    print(f"Reading from BUF_FILE = {BUF_FILE}")
    with open(BUF_FILE, 'r') as file:    
        transaction_cycles = 0
        while True:
            # (0) read the latest line, place into window
            line = file.readline()
            if not line:
                sleep(0.5)
                continue
            line = line.strip()
            # if not line: continue
            transaction_cycles += 1
            
            # ***************** SINGLE TRANSACTION TESTS *****************
            # (1) acquire the rules score (simple rules, known ips, etc.)   --> leave for 404/discard: this is NOT great for random traffic 
            
            # (2) acquire the model score (isolation forest outlier)        --> leave for 404/discard: maybe, depends if forest model is capable enough
            
            # (3) calculate the anomaly score (rules + model score)         --> leave for 404/discard
            
            # (4) API post request (anomalous transaction)                  --> leave for 404/discard
            # ************************************************************
            
            # ******************* SLIDING WINDOW TESTS *******************
            # (5) Add line to the corresponding window (prev. 100 transactions)
            place_in_window(copy.deepcopy(line))
            
            # (6) Get the XGBoost window score (line is passed through to know which global window to look at)
            if len(CONN_WINDOW) == WINDOW_SIZE:
                prediction, window_score = get_window_score()
                print(f"{prediction} | {window_score}")
                print(f"Lines read: {transaction_cycles}")
                CONN_WINDOW.clear()
            
            
            # (7) API post request (anomalous patterns)                     
            
            # ************************************************************
            
            # sleep(1)

    return 0   

main()
    
import joblib
import argparse
import os
from time import sleep
from collections import deque
import pandas as pd
import numpy as np
import xgb
import copy

import requests

# === LOAD TRAINING SCHEMA ===
# We must load a CSV used in training because THAT defines column order + names.
TRAIN_SCHEMA = pd.read_csv(
    "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",
    nrows=1
).columns.tolist()

# The model was trained on whatever numeric columns existed in CSVs
DUMMY_DF = pd.read_csv("../../train_test_data/new-benign_10_min/csv/child1/conn.csv", nrows=50)
TRAIN_NUMERIC_COLS = DUMMY_DF.select_dtypes(include=[np.number]).columns.tolist()

BUF_FILE = "../../buf/buffer.csv"

# # models
# conn_model = joblib.load("/home/gabrieltoro45/capstone/pdml/src/python/models/conn_model.joblib")  # DESKTOP
conn_model = joblib.load("/mnt/c/Users/gabri/Desktop/School/capstone/pdml/src/python/models/conn_model.joblib")  # LAPTOP
# conn_model = joblib.load("/home/child4/Desktop/team2/pdml/src/python/models/conn_model.joblib")     # CLUSTER (Child 4)
# conn_model = joblib.load("/home/child2/Desktop/team2/pdml/src/python/models/conn_model.joblib")     # CLUSTER (Child 2)
# conn_model = joblib.load("/home/child1/Desktop/team2/pdml/src/python/models/conn_model.joblib")     # CLUSTER (Child 1)

# buffers (priority queues for broader statistical analysis, sorted by timestamp)
conn_count = 0
WINDOW_SIZE = 200
CONN_WINDOW = deque(maxlen=WINDOW_SIZE)

def place_in_window(line: str):
    if not line:
        return

    line = line[5:]     # get rid of 'CONN,' at beginning of the line
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


# ==== Helper Functions ====
def send_request(window_score, severity):
    # Send the API request (**404 Integration**)
    IP = "192.168.50.32"    # Child 4 IP contains Visualization API
    PORT = 4000             # Exposed port
    TOKEN = "b862d2b4f286bfe0ace308a577b402fce3fca9a94980509cdd5a7d7995089568"  # X-Internal-Token value
    CONF = severity
    
    url = f"http://{IP}:{PORT}/internal/alert"
    payload = {
        "source": "pdml-subsystem-child-4",
        "type": "malignant-transaction-window",
        "severity": CONF,
        "confidence": float(window_score),  # must be 0.0–1.0 (DB check constraint)
        "message": "Remote connectivity test",
        "data": {"from": "child 4"},
    }

    r = requests.post(url, json=payload, headers={"X-Internal-Token": TOKEN})
    # print(r.status_code, r.text)
    return

# ==== Main Function ====
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ORANGE = '\033[38;5;208m'
    RESET = '\033[0m'

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
                if window_score >= 0.9:
                    print(f"{Colors.RED}{prediction} | {window_score:.4f} <-- Anomalous Window{Colors.RESET}")
                    send_request(window_score, "severe")
                elif window_score >= 0.7:
                    print(f"{Colors.ORANGE}{prediction} | {window_score:.4f} <-- Suspicious Window{Colors.RESET}")
                    send_request(window_score, "suspicious")
                elif window_score >= 0.5:
                    print(f"{Colors.YELLOW}{prediction} | {window_score:.4f} <-- Flagged Window{Colors.RESET}")
                    send_request(window_score, "flagged")
                else:
                    print(f"{Colors.GREEN}{prediction} | {window_score:.4f}{Colors.RESET}")
                print(f"Lines processed: {transaction_cycles}")
                CONN_WINDOW.clear()
    return 0   

main()
    
import pandas as pd

paths_to_concat = [
    "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_conn.csv",           # [0]
    "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_conn.csv",           # [1]
    "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",                                 # [7]
    "../../train_test_data/new-benign_10_min/csv/child2/conn.csv"                                 # [8]
]

filepath = "../../train_test_data/combined_benign_conn.csv"

concat = None
for path in paths_to_concat:
    df = pd.read_csv(path)
    concat = pd.concat([df])
concat.to_csv(filepath, index=False)    

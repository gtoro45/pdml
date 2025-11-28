import pandas as pd

paths_to_concat = [
    "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",
    "../../train_test_data/lidar-attack/csv/child2/conn.csv",
    "../../train_test_data/new-benign_10_min/csv/child2/conn.csv"
]

filepath = "../../train_test_data/combined_benign_conn_BNB.csv"

dfs = []
for path in paths_to_concat:
    df = pd.read_csv(path)
    dfs.append(df)

concat = pd.concat(dfs, ignore_index=True)
concat.to_csv(filepath, index=False)    

# Concat raw Zeek log files for testing

import pandas as pd

paths_to_concat = [
    "../../train_test_data/new-benign_10_min/child1/conn.log",
    "../../train_test_data/lidar-attack/child2/conn.log",
    "../../train_test_data/new-benign_10_min/child2/conn.log"
]

all_lines = []
for i in range(len(paths_to_concat)):
    with open(paths_to_concat[i], 'r') as conn_file:
        lines = conn_file.readlines()
        if i != 0:
            lines = lines[8:]
        for line in lines:
            if "#close" in line: continue
            all_lines.append(line.strip('\n'))

for line in all_lines:
    print(line)             # unix output redirection to destination file is easiest
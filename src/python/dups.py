import pandas as pd
import glob

# old zeek conn long data
benign_file1 = "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv"
benign_file2 = "../../train_test_data/new-benign_10_min/csv/child1/conn.csv"
benign_file3 = "../../train_test_data/new-benign_10_min/csv/child2/conn.csv"

attack_file1 = "../../train_test_data/lidar-attack/csv/lidar-pod/conn.csv"
attack_file2 = "../../train_test_data/lidar-attack/csv/child1/conn.csv"
attack_file3 = "../../train_test_data/lidar-attack/csv/child2/conn.csv"

benigns = [benign_file1, benign_file2, benign_file3]
attacks = [attack_file1, attack_file2, attack_file3]

print("Duplicates in Benign Data:")
for file in benigns:
    print(file, end=": ")
    df = pd.read_csv(file, low_memory=False)
    cols = [c for c in df.columns if c not in ('ts', 'uid', 'tunnel_parents')]
    dups = df.duplicated(subset=cols, keep=False).sum()
    print(f"{dups} ({100 * (dups / df.size):.2f}% of file)")
    # Group to see which transactions are duped and how many times
    # dups = df.groupby(cols).size().reset_index(name='count').query('count > 1')
    # print(dups)

print("\nDuplicates in Attack Data:")    
for file in attacks:
    print(file, end=": ")
    df = pd.read_csv(file, low_memory=False)
    cols = [c for c in df.columns if c not in ('ts', 'uid', 'tunnel_parents')]
    dups = df.duplicated(subset=cols, keep=False).sum()
    print(f"{dups} ({100 * (dups / df.size):.2f}% of file)")
    # Group to see which transactions are duped and how many times
    # dups = df.groupby(cols).size().reset_index(name='count').query('count > 1')
    # print(dups)

print("\n**********************************************************************************************\n")

# new pcapng data [As PCAPNG csv format]
root = "../../train_test_data/KUBEDATA"
benigns = glob.glob(root + '/benign/**/*.csv', recursive=True)
attacks = glob.glob(root + '/lidar-attack/**/*.csv', recursive=True)

print("Duplicates in Benign Data:")
for file in benigns:
    print(file, end=": ")
    df = pd.read_csv(file, low_memory=False)
    cols = [c for c in df.columns if c not in ('frame_number', 'ts', 'iat', 'eth_src', 'eth_dst')]
    dups = df.duplicated(subset=cols, keep=False).sum()
    print(f"{dups} ({100 * (dups / df.size):.2f}% of file)")
    # Group to see which transactions are duped and how many times
    # dups = df.groupby(cols).size().reset_index(name='count').query('count > 1')
    # print(dups)

print("\nDuplicates in Attack Data:")    
for file in attacks:
    print(file, end=": ")
    df = pd.read_csv(file, low_memory=False)
    cols = [c for c in df.columns if c not in ('frame_number', 'ts', 'iat', 'eth_src', 'eth_dst')]
    dups = df.duplicated(subset=cols, keep=False).sum()
    print(f"{dups} ({100 * (dups / df.size):.2f}% of file)")
    # Group to see which transactions are duped and how many times
    # dups = df.groupby(cols).size().reset_index(name='count').query('count > 1')
    # print(dups)

print("\n**********************************************************************************************\n")
    
# new PCAPNG data [raw PCAPNG ran through Zeek for conn.log]
root = "../../train_test_data/KUBEDATA"
benigns = glob.glob(root + '/benign-conn-csv/**/*.csv', recursive=True)
attacks = glob.glob(root + '/lidar-attack-conn-csv/**/*.csv', recursive=True)

print("Duplicates in Benign Data:")
for file in benigns:
    print(file, end=": ")
    df = pd.read_csv(file, low_memory=False)
    cols = [c for c in df.columns if c not in ('ts', 'uid', 'tunnel_parents')]
    dups = df.duplicated(subset=cols, keep=False).sum()
    print(f"{dups} ({100 * (dups / df.size):.2f}% of file)")
    # Group to see which transactions are duped and how many times
    # dups = df.groupby(cols).size().reset_index(name='count').query('count > 1')
    # print(dups)

print("\nDuplicates in Attack Data:")    
for file in attacks:
    print(file, end=": ")
    df = pd.read_csv(file, low_memory=False)
    cols = [c for c in df.columns if c not in ('ts', 'uid', 'tunnel_parents')]
    dups = df.duplicated(subset=cols, keep=False).sum()
    print(f"{dups} ({100 * (dups / df.size):.2f}% of file)")
    # Group to see which transactions are duped and how many times
    # dups = df.groupby(cols).size().reset_index(name='count').query('count > 1')
    # print(dups)
import pandas as pd
import numpy as np
import os

# -----------------------------------------------------------
# POD-SPECIFIC PATHS (benign[i] corresponds to attack[i])
# -----------------------------------------------------------
benign_paths = {
    "child1": "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",
    "child2": "../../train_test_data/new-benign_10_min/csv/child2/conn.csv",
    "cam":    "../../train_test_data/new-benign_10_min/csv/cam-pod/conn.csv",
    "lidar":  "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv",
    "nginx":  "../../train_test_data/new-benign_10_min/csv/nginx-pod/conn.csv",
}

attack_paths = {
    "child1": "../../train_test_data/lidar-attack/csv/child1/conn.csv",
    "child2": "../../train_test_data/lidar-attack/csv/child2/conn.csv",
    "cam":    "../../train_test_data/lidar-attack/csv/cam-pod/conn.csv",
    "lidar":  "../../train_test_data/lidar-attack/csv/lidar-pod/conn.csv",
    "nginx":  "../../train_test_data/lidar-attack/csv/nginx-pod/conn.csv",
}



# -----------------------------------------------------------
# LOAD ONE POD’S BENIGN + ATTACK
# -----------------------------------------------------------
def load_pod(pod_name):
    benign = pd.read_csv(benign_paths[pod_name])
    attack = pd.read_csv(attack_paths[pod_name])
    print(f"[{pod_name}] benign={len(benign)}, attack={len(attack)}")
    return benign, attack

# -----------------------------------------------------------
# MIX TYPE A: benign → attack
# -----------------------------------------------------------
def make_mix_A(benign_df, attack_df, benign_ratio=0.5):
    n_benign = int(len(benign_df) * benign_ratio)
    benign_part = benign_df.sample(n_benign, random_state=42)
    attack_part = attack_df.sample(len(attack_df), random_state=42)
    return pd.concat([benign_part, attack_part], ignore_index=True)

# -----------------------------------------------------------
# MIX TYPE B: attack → benign
# -----------------------------------------------------------
def make_mix_B(benign_df, attack_df, benign_ratio=0.5):
    n_benign = int(len(benign_df) * benign_ratio)
    benign_part = benign_df.sample(n_benign, random_state=42)
    attack_part = attack_df.sample(len(attack_df), random_state=42)
    return pd.concat([attack_part, benign_part], ignore_index=True)

# -----------------------------------------------------------
# MIX TYPE C: random blend
# -----------------------------------------------------------
def make_mix_C(benign_df, attack_df, attack_fraction=0.3):
    """
    attack_fraction controls *fraction of attack_df selected*.
    """
    n_attack = int(attack_fraction * len(attack_df))
    n_benign = int((1 - attack_fraction) * len(benign_df))

    attack_part = attack_df.sample(n_attack, random_state=42)
    benign_part = benign_df.sample(n_benign, random_state=42)

    out = pd.concat([benign_part, attack_part], ignore_index=True)
    return out.sample(len(out), random_state=42).reset_index(drop=True)

# -----------------------------------------------------------
# MIX TYPE D: alternating windows
# -----------------------------------------------------------
def make_mix_D(benign_df, attack_df, window_size=500):
    out = []
    i = 0
    j = 0

    while i < len(benign_df) or j < len(attack_df):

        if i < len(benign_df):
            out.append(benign_df.iloc[i:i+window_size])
            i += window_size

        if j < len(attack_df):
            out.append(attack_df.iloc[j:j+window_size])
            j += window_size

    return pd.concat(out, ignore_index=True)

# -----------------------------------------------------------
# MIX TYPE E: benign --> mixed --> benign
# -----------------------------------------------------------
def make_BMB(benign_df, mixed_df, 
             benign_windows_before=3,
             mixed_windows=2,
             benign_windows_after=3,
             window_size=100):

    parts = []

    # --- 1. Benign segment (before mixed) ---
    b1_total = benign_windows_before * window_size
    benign_before = benign_df.sample(b1_total, random_state=10)
    parts.append(benign_before)

    # --- 2. Mixed segment (benign+attack blend) ---
    m_total = mixed_windows * window_size
    mixed_part = mixed_df.sample(m_total, random_state=11)
    parts.append(mixed_part)

    # --- 3. Benign segment (after mixed) ---
    b2_total = benign_windows_after * window_size
    benign_after = benign_df.sample(b2_total, random_state=12)
    parts.append(benign_after)

    # Combine segments sequentially
    out = pd.concat(parts, ignore_index=True)
    return out


# -----------------------------------------------------------
# GENERATE MIXES PER POD
# -----------------------------------------------------------
# output folder
OUT_DIR = "../../train_test_data/mixed-lidar-attack/"
os.makedirs(OUT_DIR, exist_ok=True)

for pod in benign_paths.keys():

    benign_df, attack_df = load_pod(pod)

    mixA = make_mix_A(benign_df, attack_df, benign_ratio=0.5)
    mixB = make_mix_B(benign_df, attack_df, benign_ratio=0.5)
    mixC = make_mix_C(benign_df, attack_df, attack_fraction=0.3)
    mixD = make_mix_D(benign_df, attack_df, window_size=500)
    
    # one last mixed set: benign --> mixed --> benign
    BMB = make_BMB(
        benign_df, 
        mixed_df=mixC, 
        benign_windows_before=3, 
        mixed_windows=2, 
        benign_windows_after=3,
        window_size=100
    )

    # --- create output folder per pod ---
    pod_dir = os.path.join(OUT_DIR, pod)
    os.makedirs(pod_dir, exist_ok=True)

    mixA.to_csv(f"{pod_dir}/mixed_A.csv", index=False)
    mixB.to_csv(f"{pod_dir}/mixed_B.csv", index=False)
    mixC.to_csv(f"{pod_dir}/mixed_C.csv", index=False)
    mixD.to_csv(f"{pod_dir}/mixed_D.csv", index=False)
    BMB.to_csv(f"{pod_dir}/mixed_BNB.csv", index=False)

    print(f"[{pod}] DONE writing mixed sets.")

print("All pod-specific mixed datasets generated.")

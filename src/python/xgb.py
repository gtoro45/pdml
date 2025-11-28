import pandas as pd
import numpy as np
from scipy.stats import entropy
from xgboost import XGBClassifier
import joblib

def window_features(df, window_size=200):
    """
    Convert row-level Zeek conn data into window-level statistical features.
    This fixes the fundamental problem in your current ML pipeline.
    """
    windows = []
    num_rows = len(df)

    for start in range(0, num_rows, window_size):
        chunk = df.iloc[start:start + window_size]

        if len(chunk) == 0:
            continue

        # numerical columns only
        numeric = chunk.select_dtypes(include=[np.number])

        if numeric.shape[1] == 0:
            continue

        arr = numeric.to_numpy()

        # Feature construction
        feats = {
            "mean": np.mean(arr, axis=0),
            "std": np.std(arr, axis=0),
            "min": np.min(arr, axis=0),
            "max": np.max(arr, axis=0),
            "entropy": entropy(np.abs(arr).mean(axis=0) + 1e-12)
        }

        # flatten
        feat_vec = []
        for k in ["mean", "std", "min", "max"]:
            feat_vec.extend(feats[k])

        feat_vec.append(feats["entropy"])
        windows.append(feat_vec)

    return pd.DataFrame(windows)

def train_xgb_window(X_benign, X_attack, window_size=200):
    Xb = window_features(X_benign, window_size=window_size)
    Xa = window_features(X_attack, window_size=window_size)

    yb = np.zeros(len(Xb))
    ya = np.ones(len(Xa))

    X = pd.concat([Xb, Xa], ignore_index=True)
    y = np.concatenate([yb, ya])

    model = XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=-1,
        tree_method="hist",
        eval_metric="logloss"
    )
    model.fit(X, y)
    return model

def evaluate_on_windows(model, df, label_name, window_size=200):
    Xw = window_features(df, window_size)

    preds = model.predict(Xw)

    total = len(preds)
    detected = preds.sum()  # 1 = attack
    benign_flagged = (preds == 1).sum()  # if evaluating benign

    print("***********************************************************************")
    print(f"TEST SET: {label_name}")
    print(f"Total windows:     {total}")

    if label_name.lower().startswith("benign"):
        print(f"False positives:   {benign_flagged}")
        print(f"False positive rate: {benign_flagged / total:.2%}")
    else:
        print(f"Detected attacks:  {detected}")
        print(f"Detection rate:    {detected / total:.2%}")

    print("***********************************************************************")



#############################################################
# 4. MAIN TEST HARNESS (UPDATED: mixed sets NOT used for training)
#############################################################
def main():
    # --------------------------------------------------------
    # PURE BENIGN TRAINING SETS
    # --------------------------------------------------------
    benign_paths = [
        "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",
        "../../train_test_data/new-benign_10_min/csv/child2/conn.csv",
        "../../train_test_data/new-benign_10_min/csv/cam-pod/conn.csv",
        "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv",
        "../../train_test_data/new-benign_10_min/csv/nginx-pod/conn.csv",
    ]

    # --------------------------------------------------------
    # PURE ATTACK TRAINING SETS
    # --------------------------------------------------------
    pure_attack_paths = [
        "../../train_test_data/lidar-attack/csv/child1/conn.csv",
        "../../train_test_data/lidar-attack/csv/child2/conn.csv",
        "../../train_test_data/lidar-attack/csv/cam-pod/conn.csv",
        "../../train_test_data/lidar-attack/csv/lidar-pod/conn.csv",
        "../../train_test_data/lidar-attack/csv/nginx-pod/conn.csv",
    ]

    # --------------------------------------------------------
    # MIXED TEST-ONLY SETS (NOT USED FOR TRAINING)
    # --------------------------------------------------------
    mixed_attack_paths = [
        "../../train_test_data/mixed-lidar-attack/child1/mixed_A.csv",
        "../../train_test_data/mixed-lidar-attack/child1/mixed_B.csv",
        "../../train_test_data/mixed-lidar-attack/child1/mixed_C.csv",
        "../../train_test_data/mixed-lidar-attack/child1/mixed_D.csv",
        "../../train_test_data/mixed-lidar-attack/child1/mixed_BNB.csv",
        
        "../../train_test_data/mixed-lidar-attack/child2/mixed_A.csv",
        "../../train_test_data/mixed-lidar-attack/child2/mixed_B.csv",
        "../../train_test_data/mixed-lidar-attack/child2/mixed_C.csv",
        "../../train_test_data/mixed-lidar-attack/child2/mixed_D.csv",
        "../../train_test_data/mixed-lidar-attack/child2/mixed_BNB.csv",
        
        "../../train_test_data/mixed-lidar-attack/cam/mixed_A.csv",
        "../../train_test_data/mixed-lidar-attack/cam/mixed_B.csv",
        "../../train_test_data/mixed-lidar-attack/cam/mixed_C.csv",
        "../../train_test_data/mixed-lidar-attack/cam/mixed_D.csv",
        "../../train_test_data/mixed-lidar-attack/cam/mixed_BNB.csv",
        
        "../../train_test_data/mixed-lidar-attack/lidar/mixed_A.csv",
        "../../train_test_data/mixed-lidar-attack/lidar/mixed_B.csv",
        "../../train_test_data/mixed-lidar-attack/lidar/mixed_C.csv",
        "../../train_test_data/mixed-lidar-attack/lidar/mixed_D.csv",
        "../../train_test_data/mixed-lidar-attack/lidar/mixed_BNB.csv",
        
        "../../train_test_data/mixed-lidar-attack/nginx/mixed_A.csv",
        "../../train_test_data/mixed-lidar-attack/nginx/mixed_B.csv",
        "../../train_test_data/mixed-lidar-attack/nginx/mixed_C.csv",
        "../../train_test_data/mixed-lidar-attack/nginx/mixed_D.csv",
        "../../train_test_data/mixed-lidar-attack/nginx/mixed_BNB.csv"
    ]

    # --------------------------------------------------------
    # Load datasets
    # --------------------------------------------------------
    benign_dfs = [pd.read_csv(p) for p in benign_paths]
    pure_attack_dfs = [pd.read_csv(p) for p in pure_attack_paths]
    mixed_attack_dfs = [pd.read_csv(p) for p in mixed_attack_paths]

    # Training sets
    X_benign_train = pd.concat(benign_dfs, ignore_index=True)
    X_attack_train = pd.concat(pure_attack_dfs, ignore_index=True)

    # --------------------------------------------------------
    # Train models
    # --------------------------------------------------------
    WINDOW_SIZES = [200]
    for WINDOW_SIZE in WINDOW_SIZES:
        # print(f"\n### Training Window-Based Random Forest (WINDOW_SIZE = {WINDOW_SIZE}) ###")
        # rf_model = train_rf_window(X_benign_train, X_attack_train, window_size=WINDOW_SIZE)

        print(f"\n### Training Window-Based XGBoost (WINDOW_SIZE = {WINDOW_SIZE}) ###")
        xgb_model = train_xgb_window(X_benign_train, X_attack_train, window_size=WINDOW_SIZE)
        joblib.dump(xgb_model, "./models/conn_model.joblib")
        
        # --------------------------------------------------------
        # Evaluate — pure benign first
        # --------------------------------------------------------
        print("\n\n### XGBOOST RESULTS ###")
        for path, df in zip(benign_paths, benign_dfs):
            evaluate_on_windows(xgb_model, df, "BENIGN (pure): " + path, window_size=WINDOW_SIZE)
        print()
        
        # # --------------------------------------------------------
        # # Evaluate — pure attack
        # # --------------------------------------------------------
        for path, df in zip(pure_attack_paths, pure_attack_dfs):
            evaluate_on_windows(xgb_model, df, "ATTACK (pure): " + path, window_size=WINDOW_SIZE)
        print()
        
        # # --------------------------------------------------------
        # # Evaluate — mixed attack sets
        # # --------------------------------------------------------
        for path, df in zip(mixed_attack_paths, mixed_attack_dfs):
            evaluate_on_windows(xgb_model, df, "ATTACK (mixed): " + path, window_size=WINDOW_SIZE)
        print()
    

#############################################################
# RUN IT
#############################################################
if __name__ == "__main__":
    main()

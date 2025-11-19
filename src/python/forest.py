# random forest training and usage program for outlier detection
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from encoding import *
import matplotlib.pyplot as plt

def train_and_test_iter(paths):
    # train on 1 of the 5 data sets, and test on the remaining 4
    # do this to see relative strength of training sets
    for i in range(len(paths)):
        if i == 5: break    # want to train only on benign data
        train_path = paths[i]
        print("************************************************************************")
        print(f"Model Trained with [{train_path}]")
        print("************************************************************************\n")
        # prepare the training data, encoder, and frequency mappings
        X, encoder = encode_training_data(train_path, fit_encoder=True)

        # initialize the isolation forest
        iso_forest = IsolationForest(
            n_estimators=500,
            contamination=0.02, # maximum provided in FSR
            random_state=42
        )

        # train the model
        iso_forest.fit(X)
        
        # test the model on all the sets
        for j in range(len(paths)):
            test_path = paths[j]
            if(i is not j) and (j < 5):
                print(f"Test set: {test_path}")
            elif j == 5:
                print(f"Test set: {test_path} \t\t\t <-- BENIGN")
            elif j == 6:
                print(f"Test set: {test_path} \t\t\t <-- MALIGNANT")
            else:
                print(f"Test set: {test_path} \t\t\t <-- same as training data")

            # prepare the test data
            df_test = pd.read_csv(test_path)
            X_test = encode_training_data(test_path, encoder=encoder, fit_encoder=False)[0]

            # predict anomalies and get scores
            y_pred = iso_forest.predict(X_test)
            scores = iso_forest.decision_function(X_test)
            results = df_test.copy()
            results["anomaly_label"] = y_pred
            results["anomaly_score"] = scores

            # Count false positives (should be near zero)
            if 'malignant' not in test_path:
                false_positives = (y_pred == -1).sum()
                total = len(y_pred)
                print(f"Total benign test samples: {total}")
                print(f"False positives: {false_positives}")
                print(f"False positive rate: {false_positives / total:.4%}\n")
            else:
                flagged_transactions = (y_pred == -1).sum()
                total_transactions = len(y_pred)
                print(f"Total test samples: {total_transactions}")
                print(f"Number of flagged transactions: {flagged_transactions}")
                print(f"Accuracy: {flagged_transactions / total_transactions:.4%}")
        print("************************************************************************\n")


# CONN
def test_modular_conn():
    # specify the paths
    conn_paths = [
        "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_conn.csv",           # [0]
        "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_conn.csv",           # [1]
        "../../train_test_data/benign_1_min/cam-pod/csv files/camera_conn.csv",                 # [2]
        "../../train_test_data/benign_1_min/lidar-pod/csv files/lidar_conn.csv",                # [3]
        "../../train_test_data/benign_1_min/nginx-pod/csv files/NGINX_conn.csv",                # [4]
        "../../train_test_data/benign_sim/csv/conn.csv",                                        # [5] benign
        "../../train_test_data/ddos_sim/csv/conn_malignant1.csv",                               # [6] malignant
        
        # NEW BENIGN DATA PATHS
        "../../train_test_data/new-benign/csv/child1/conn.csv",                                 # [7]
        "../../train_test_data/new-benign/csv/child2/conn.csv",                                 # [8]
        "../../train_test_data/new-benign/csv/cam-pod/conn.csv",                                # [9]
        "../../train_test_data/new-benign/csv/lidar-pod/conn.csv",                              # [10]
        "../../train_test_data/new-benign/csv/nginx-pod/conn.csv",                              # [11]
        
        
        # NEW MALIGNANT DATA PATHS
        "../../train_test_data/lidar-attack/csv/child1/conn.csv",                               # [12]
        "../../train_test_data/lidar-attack/csv/child2/conn.csv",                               # [13]
        "../../train_test_data/lidar-attack/csv/cam-pod/conn.csv",                              # [14]
        "../../train_test_data/lidar-attack/csv/lidar-pod/conn.csv",                            # [15]
        "../../train_test_data/lidar-attack/csv/nginx-pod/conn.csv"                             # [16]
    ]
    
    # encode and COMBINED training data
    path1 = conn_paths[0]
    path2 = conn_paths[1]
    path3 = conn_paths[2]
    # path4 = conn_paths[3]
    path5 = conn_paths[4]
    path6 = conn_paths[5] # test benign set we made
    path7 = conn_paths[7]
    path8 = conn_paths[8]
    

    X1, encoder = encode_training_data(path1, fit_encoder=True, exclude_incomplete=True)
    X2, _ = encode_training_data(path2, encoder=encoder, fit_encoder=False, exclude_incomplete=True)
    X3, _ = encode_training_data(path3, encoder=encoder, fit_encoder=False, exclude_incomplete=True)
    # X4, _ = encode_training_data(path4, encoder=encoder, fit_encoder=False, exclude_incomplete=True)
    X5, _ = encode_training_data(path5, encoder=encoder, fit_encoder=False, exclude_incomplete=True)
    X6, _ = encode_training_data(path6, encoder=encoder, fit_encoder=False, exclude_incomplete=True)
    X7, _ = encode_training_data(path7, encoder=encoder, fit_encoder=False, exclude_incomplete=True)
    X8, _ = encode_training_data(path8, encoder=encoder, fit_encoder=False, exclude_incomplete=True)
    X = pd.concat([X1, X2, X3, X5, X6, X7, X8], ignore_index=True)
    # X = X1
    print(f"Training dataset size={len(X)}")

    # initialize the isolation forest
    iso_forest = IsolationForest(
        n_estimators=500,
        contamination=0.02, # maximum provided in FSR
        random_state=42,
        n_jobs=-1
    )

    # train the model
    iso_forest.fit(X)

        # encode test data
    X_train1, _ = encode_training_data(conn_paths[0], encoder=encoder, fit_encoder=False)
    X_train2, _ = encode_training_data(conn_paths[1], encoder=encoder, fit_encoder=False)
    X_train3, _ = encode_training_data(conn_paths[7], encoder=encoder, fit_encoder=False)
    X_train4, _ = encode_training_data(conn_paths[8], encoder=encoder, fit_encoder=False)
    
    X_live, _  = encode_training_data(conn_paths[5],  encoder=encoder, fit_encoder=False)
    X_ddos, _  = encode_training_data(conn_paths[6],  encoder=encoder, fit_encoder=False)
    X_attack1, _ = encode_training_data(conn_paths[12], encoder=encoder, fit_encoder=False)
    X_attack2, _ = encode_training_data(conn_paths[13], encoder=encoder, fit_encoder=False)
    X_attack3, _ = encode_training_data(conn_paths[14], encoder=encoder, fit_encoder=False)
    X_attack4, _ = encode_training_data(conn_paths[15], encoder=encoder, fit_encoder=False)
    X_attack5, _ = encode_training_data(conn_paths[16], encoder=encoder, fit_encoder=False)

    # run the model on test data
    y_train1 = iso_forest.predict(X_train1)
    y_train2 = iso_forest.predict(X_train2)
    y_train3 = iso_forest.predict(X_train3)
    y_train4 = iso_forest.predict(X_train4)

    y_live  = iso_forest.predict(X_live)
    y_ddos  = iso_forest.predict(X_ddos)

    y_attack1 = iso_forest.predict(X_attack1)
    y_attack2 = iso_forest.predict(X_attack2)
    y_attack3 = iso_forest.predict(X_attack3)
    y_attack4 = iso_forest.predict(X_attack4)
    y_attack5 = iso_forest.predict(X_attack5)

    scores_train1 = iso_forest.decision_function(X_train1)
    scores_train2 = iso_forest.decision_function(X_train2)
    scores_train3 = iso_forest.decision_function(X_train3)
    scores_train4 = iso_forest.decision_function(X_train4)

    scores_live  = iso_forest.decision_function(X_live)
    scores_ddos  = iso_forest.decision_function(X_ddos)

    scores_attack1 = iso_forest.decision_function(X_attack1)
    scores_attack2 = iso_forest.decision_function(X_attack2)
    scores_attack3 = iso_forest.decision_function(X_attack3)
    scores_attack4 = iso_forest.decision_function(X_attack4)
    scores_attack5 = iso_forest.decision_function(X_attack5)

    # analyze output

    # y_train1
    print("***********************************************************************")
    print(f"Test set: {conn_paths[0]}")
    false_positives = (y_train1 == -1).sum()
    total = len(y_train1)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")
    print("***********************************************************************")

    # y_train2
    print("***********************************************************************")
    print(f"Test set: {conn_paths[1]}")
    false_positives = (y_train2 == -1).sum()
    total = len(y_train2)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")
    print("***********************************************************************")

    # y_train3
    print("***********************************************************************")
    print(f"Test set: {conn_paths[7]}")
    false_positives = (y_train3 == -1).sum()
    total = len(y_train3)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")
    print("***********************************************************************")

    # y_train4
    print("***********************************************************************")
    print(f"Test set: {conn_paths[8]}")
    false_positives = (y_train4 == -1).sum()
    total = len(y_train4)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")
    print("***********************************************************************")

    # y_live
    print("***********************************************************************")
    print(f"Test set: {conn_paths[5]}")
    false_positives = (y_live == -1).sum()
    total = len(y_live)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")
    print("***********************************************************************")

    # y_ddos
    print("***********************************************************************")
    print(f"Test set: {conn_paths[6]}")
    flagged_transactions = (y_ddos == -1).sum()
    total_transactions = len(y_ddos)
    print(f"Total test samples: {total_transactions}")
    print(f"Number of flagged transactions: {flagged_transactions}")
    print(f"Accuracy: {flagged_transactions / total_transactions:.4%}")
    print("***********************************************************************")

    # y_attack1
    print("***********************************************************************")
    print(f"Test set: {conn_paths[12]}")
    flagged = (y_attack1 == -1).sum()
    total = len(y_attack1)
    print(f"Total attack samples: {total}")
    print(f"Detected anomalies: {flagged}")
    print(f"Detection rate: {flagged / total:.4%}\n")
    print("***********************************************************************")

    # y_attack2
    print("***********************************************************************")
    print(f"Test set: {conn_paths[13]}")
    flagged = (y_attack2 == -1).sum()
    total = len(y_attack2)
    print(f"Total attack samples: {total}")
    print(f"Detected anomalies: {flagged}")
    print(f"Detection rate: {flagged / total:.4%}\n")
    print("***********************************************************************")

    # y_attack3
    print("***********************************************************************")
    print(f"Test set: {conn_paths[14]}")
    flagged = (y_attack3 == -1).sum()
    total = len(y_attack3)
    print(f"Total attack samples: {total}")
    print(f"Detected anomalies: {flagged}")
    print(f"Detection rate: {flagged / total:.4%}\n")
    print("***********************************************************************")

    # y_attack4
    print("***********************************************************************")
    print(f"Test set: {conn_paths[15]}")
    flagged = (y_attack4 == -1).sum()
    total = len(y_attack4)
    print(f"Total attack samples: {total}")
    print(f"Detected anomalies: {flagged}")
    print(f"Detection rate: {flagged / total:.4%}\n")
    print("***********************************************************************")

    # y_attack5
    print("***********************************************************************")
    print(f"Test set: {conn_paths[16]}")
    flagged = (y_attack5 == -1).sum()
    total = len(y_attack5)
    print(f"Total attack samples: {total}")
    print(f"Detected anomalies: {flagged}")
    print(f"Detection rate: {flagged / total:.4%}\n")
    print("***********************************************************************")



    s_train1 = stats("train", scores_train1)
    s_live  = stats("live",  scores_live)
    s_ddos  = stats("ddos",  scores_ddos)

    for pct in [0.1, 0.5, 1, 2, 5, 10]:
        thresh = np.percentile(scores_train1, pct)
        r_train = (scores_train1 < thresh).mean()
        r_live  = (scores_live  < thresh).mean()
        r_ddos  = (scores_ddos  < thresh).mean()
        # print(f"pct={pct:>4}% | thresh={thresh:.6f} | train={r_train:.4%} | live={r_live:.4%} | ddos={r_ddos:.4%}")


    # print(pd.DataFrame([s_train1, s_live, s_ddos]).set_index("name").T)

    # # plot the decision functions and compute threshold (2% lowest scores)
    # threshold = np.percentile(scores_train1, 2)  # since contamination = 0.02
    # print(f"\nIsolation Forest anomaly threshold (2% cutoff): {threshold:.5f}")
    # fig, axes = plt.subplots(4, 1, figsize=(10, 8), sharex=True)

    # # 1 — training1 (benign)
    # axes[0].hist(scores_train1, bins=200, color='tab:blue', alpha=0.6)
    # axes[0].axvline(threshold, color='black', linestyle='--', label=f'Threshold = {threshold:.3f}')
    # axes[0].set_title("Train1 (benign)")
    # axes[0].set_yscale('log')
    # axes[0].legend()
    # axes[0].grid(True, linestyle='--', alpha=0.3)
    
    # # 1 — training2 (benign)
    # axes[1].hist(scores_train2, bins=200, color='tab:blue', alpha=0.6)
    # axes[1].axvline(threshold, color='black', linestyle='--', label=f'Threshold = {threshold:.3f}')
    # axes[1].set_title("Train2 (benign)")
    # axes[1].set_yscale('log')
    # axes[1].legend()
    # axes[1].grid(True, linestyle='--', alpha=0.3)

    # # 2 — live 30-min
    # axes[2].hist(scores_live, bins=200, color='tab:orange', alpha=0.6)
    # axes[2].axvline(threshold, color='black', linestyle='--')
    # axes[2].set_title("Live 30-min capture")
    # axes[2].set_yscale('log')
    # axes[2].grid(True, linestyle='--', alpha=0.3)

    # # 3 — DDoS simulation
    # axes[3].hist(scores_ddos, bins=200, color='tab:red', alpha=0.6)
    # axes[3].axvline(threshold, color='black', linestyle='--')
    # axes[3].set_title("DDoS simulation")
    # axes[3].set_yscale('log')
    # axes[3].grid(True, linestyle='--', alpha=0.3)

    # # shared x-axis label
    # plt.xlabel("Decision function score (higher = more normal)")
    # plt.tight_layout()
    # plt.show()


# DNS
def test_modular_dns():
    dns_paths = [
        "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_dns.csv",
        "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_dns.csv",
        "../../train_test_data/benign_1_min/nginx-pod/csv files/NGINX_dns.csv",
        "../../train_test_data/benign_sim/csv/dns.csv",                                          # benign
        "../../train_test_data/ddos_sim/csv/dns_malignant1.csv"                                  # malignant
    ]

    path1, path2, path3, path4, path5 = dns_paths[:5]

    X1, encoder = encode_training_data(path1, fit_encoder=True, training=True)
    # X2, _ = encode_training_data(path2, encoder=encoder, fit_encoder=False, training=True)
    # X3, _ = encode_training_data(path3, encoder=encoder, fit_encoder=False, training=True)
    # X4, _ = encode_training_data(path4, encoder=encoder, fit_encoder=False, training=True)
    # X = pd.concat([X1, X2], ignore_index=True)
    X = X1
    print(f"Training dataset size={len(X)}")

    iso_forest = IsolationForest(
        n_estimators=500,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X)

    X_train1, _ = encode_training_data(path1, encoder=encoder, fit_encoder=False)
    X_train2, _ = encode_training_data(path2, encoder=encoder, fit_encoder=False)
    X_live, _   = encode_training_data(path4, encoder=encoder, fit_encoder=False)
    X_ddos, _   = encode_training_data(path5, encoder=encoder, fit_encoder=False)

    y_train1 = iso_forest.predict(X_train1)
    y_train2 = iso_forest.predict(X_train2)
    y_live   = iso_forest.predict(X_live)
    y_ddos   = iso_forest.predict(X_ddos)

    scores_train1 = iso_forest.decision_function(X_train1)
    scores_train2 = iso_forest.decision_function(X_train2)
    scores_live   = iso_forest.decision_function(X_live)
    scores_ddos   = iso_forest.decision_function(X_ddos)

    # Print analysis results (same layout)
    for i, (name, y, path) in enumerate([
        ("Train1", y_train1, path1),
        ("Train2", y_train2, path2),
        ("Live (benign)", y_live, path4),
        ("DDoS (malignant)", y_ddos, path5),
    ]):
        print("***********************************************************************")
        print(f"Test set: {path}")
        flagged = (y == -1).sum()
        total = len(y)
        print(f"Total samples: {total}")
        if "DDoS" in name:
            print(f"Flagged anomalies: {flagged}")
            print(f"Detection rate: {flagged / total:.4%}")
        else:
            print(f"False positives: {flagged}")
            print(f"False positive rate: {flagged / total:.4%}")
        print("***********************************************************************")

    threshold = np.percentile(scores_train1, 2)
    print(f"\nIsolation Forest anomaly threshold (2% cutoff): {threshold:.5f}")

    fig, axes = plt.subplots(4, 1, figsize=(10, 8), sharex=True)
    datasets = [
        ("Train1 (benign)", scores_train1, 'tab:blue'),
        ("Train2 (benign)", scores_train2, 'tab:blue'),
        ("Live 30-min capture", scores_live, 'tab:orange'),
        ("DDoS simulation", scores_ddos, 'tab:red'),
    ]
    for ax, (title, scores, color) in zip(axes, datasets):
        ax.hist(scores, bins=200, color=color, alpha=0.6)
        ax.axvline(threshold, color='black', linestyle='--')
        ax.set_title(title)
        ax.set_yscale('log')
        ax.grid(True, linestyle='--', alpha=0.3)
    plt.xlabel("Decision function score (higher = more normal)")
    plt.tight_layout()
    plt.show()


# SSL
def test_modular_ssl():
    ssl_paths = [
        "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_ssl.csv",
        "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_ssl.csv",
        "../../train_test_data/benign_sim/csv/ssl.csv",                                          # benign
        "../../train_test_data/ddos_sim/csv/ssl_malignant1.csv"                                  # malignant
    ]

    path1, path2, path3, path4 = ssl_paths[:4]

    X1, encoder = encode_training_data(path1, fit_encoder=True, training=True)
    X2, _ = encode_training_data(path2, encoder=encoder, fit_encoder=False, training=True)
    X3, _ = encode_training_data(path3, encoder=encoder, fit_encoder=False, training=True)
    X = pd.concat([X1], ignore_index=True)
    # X = X1
    print(X)
    print(f"Training dataset size={len(X)}")

    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X)

    X_train1, _ = encode_training_data(path1, encoder=encoder, fit_encoder=False)
    X_train2, _ = encode_training_data(path2, encoder=encoder, fit_encoder=False)
    X_live, _   = encode_training_data(path3, encoder=encoder, fit_encoder=False)
    X_ddos, _   = encode_training_data(path4, encoder=encoder, fit_encoder=False)

    y_train1 = iso_forest.predict(X_train1)
    y_train2 = iso_forest.predict(X_train2)
    y_live   = iso_forest.predict(X_live)
    y_ddos   = iso_forest.predict(X_ddos)

    scores_train1 = iso_forest.decision_function(X_train1)
    scores_train2 = iso_forest.decision_function(X_train2)
    scores_live   = iso_forest.decision_function(X_live)
    scores_ddos   = iso_forest.decision_function(X_ddos)

    for i, (name, y, path) in enumerate([
        ("Train1", y_train1, path1),
        ("Train2", y_train2, path2),
        ("Live (benign)", y_live, path3),
        ("DDoS (malignant)", y_ddos, path4),
    ]):
        print("***********************************************************************")
        print(f"Test set: {path}")
        flagged = (y == -1).sum()
        total = len(y)
        print(f"Total benign samples: {total}")
        print(f"False positives: {flagged}")
        print(f"False positive rate: {flagged / total:.4%}")
        print("***********************************************************************")

    threshold = np.percentile(scores_train1, 2)
    print(f"\nIsolation Forest anomaly threshold (2% cutoff): {threshold:.5f}")

    fig, axes = plt.subplots(4, 1, figsize=(10, 6), sharex=True)
    datasets = [
        ("Train1 (benign)", scores_train1, 'tab:blue'),
        ("Train2 (benign)", scores_train2, 'tab:blue'),
        ("Live (benign)", y_live, 'tab:orange'),
        ("DDoS (malignant)", y_ddos, 'tab:red'),
    ]
    for ax, (title, scores, color) in zip(axes, datasets):
        ax.hist(scores, bins=200, color=color, alpha=0.6)
        ax.axvline(threshold, color='black', linestyle='--')
        ax.set_title(title)
        ax.set_yscale('log')
        ax.grid(True, linestyle='--', alpha=0.3)
    plt.xlabel("Decision function score (higher = more normal)")
    plt.tight_layout()
    plt.show()


# test a split-forest approach, where one model is trained on 'zero feature' rows, and the other isnt
# relies on a ['zero_activity'] column present in the df
def test_split_forests():
    # specify the paths
    conn_paths = [
        "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_conn.csv",
        "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_conn.csv",
        "../../train_test_data/benign_1_min/cam-pod/csv files/camera_conn.csv",
        "../../train_test_data/benign_1_min/lidar-pod/csv files/lidar_conn.csv",
        "../../train_test_data/benign_1_min/nginx-pod/csv files/NGINX_conn.csv",
        "../../train_test_data/benign_sim/csv/conn.csv",                                          # benign
        "../../train_test_data/ddos_sim/csv/conn_malignant1.csv"                                  # malignant
    ]
    
    path1 = conn_paths[0]
    path2 = conn_paths[1]
    path3 = conn_paths[2]
    path4 = conn_paths[3]
    path5 = conn_paths[4]
    path6 = conn_paths[5]   # test benign set we made
    X1, encoder = encode_training_data(path1, fit_encoder=True, training=True)
    X2, _ = encode_training_data(path2, encoder=encoder, fit_encoder=False, training=True)
    X3, _ = encode_training_data(path3, encoder=encoder, fit_encoder=False, training=True)
    X4, _ = encode_training_data(path4, encoder=encoder, fit_encoder=False, training=True)
    X5, _ = encode_training_data(path5, encoder=encoder, fit_encoder=False, training=True)
    X6, _ = encode_training_data(path6, encoder=encoder, fit_encoder=False, training=True)
    X = pd.concat([X1, X2, X3, X4, X5, X6], ignore_index=True)
    # X = X1
    print(f"Training dataset size={len(X)}")
    
    # NEW: split into zero and nonzero activity subsets
    X_zero = X[X['zero_activity'] == 1]
    X_nonzero = X[X['zero_activity'] == 0]
    
    # NEW: Remove the label column if it exists
    feature_cols = [c for c in X.columns if c != 'label']

    # NEW: initialize and train the isolation 2 forests
    clf_zero = IsolationForest(
        n_estimators=500,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    ).fit(X_zero[feature_cols])

    clf_nonzero = IsolationForest(
        n_estimators=500,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    ).fit(X_nonzero[feature_cols])
        
    print(f"Trained clf_zero on {len(X_zero)} samples; clf_nonzero on {len(X_nonzero)} samples.")

    # NEW: extended predict function
    def predict_with_split_model(df):
        """Route samples to the correct submodel based on zero_activity."""
        preds = np.zeros(len(df), dtype=int)
        scores = np.zeros(len(df))

        mask_zero = (df['zero_activity'] == 1)
        mask_nonzero = ~mask_zero

        if mask_zero.any():
            preds[mask_zero] = clf_zero.predict(df.loc[mask_zero, feature_cols])
            scores[mask_zero] = clf_zero.decision_function(df.loc[mask_zero, feature_cols])
        if mask_nonzero.any():
            preds[mask_nonzero] = clf_nonzero.predict(df.loc[mask_nonzero, feature_cols])
            scores[mask_nonzero] = clf_nonzero.decision_function(df.loc[mask_nonzero, feature_cols])

        return preds, scores

    # encode test data
    X_train1, _ = encode_training_data(conn_paths[0], encoder=encoder, fit_encoder=False)
    X_train2, _ = encode_training_data(conn_paths[1], encoder=encoder, fit_encoder=False)
    X_live, _ = encode_training_data(conn_paths[5], encoder=encoder, fit_encoder=False)
    X_ddos, _ = encode_training_data(conn_paths[6], encoder=encoder, fit_encoder=False)

    # run the model on test data
    y_train1, scores_train1 = predict_with_split_model(X_train1)
    y_train2, scores_train2 = predict_with_split_model(X_train2)
    y_live, scores_live     = predict_with_split_model(X_live)
    y_ddos, scores_ddos     = predict_with_split_model(X_ddos)


    # analyze output
    n = 100
    # y_train1
    print("***********************************************************************")
    print(f"Test set: {conn_paths[0]}")
    false_positives = (y_train1 == -1).sum()
    total = len(y_train1)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")
    print("***********************************************************************")

    # y_train2
    print("***********************************************************************")
    print(f"Test set: {conn_paths[1]}")
    false_positives = (y_train2 == -1).sum()
    total = len(y_train2)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")
    print("***********************************************************************")

    # y_live
    print("***********************************************************************")
    print(f"Test set: {conn_paths[5]}")
    false_positives = (y_live == -1).sum()
    total = len(y_live)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")
    print("***********************************************************************")

    # y_ddos
    print("***********************************************************************")
    print(f"Test set: {conn_paths[6]}")
    flagged_transactions = (y_ddos == -1).sum()
    total_transactions = len(y_ddos)
    print(f"Total test samples: {total_transactions}")
    print(f"Number of flagged transactions: {flagged_transactions}")
    print(f"Accuracy: {flagged_transactions / total_transactions:.4%}")
    print("***********************************************************************")

def stats(name, scores):
    p = np.percentile(scores, [0,1,5,10,25,50,75,90,95,99,100])
    return pd.Series({
        "name": name,
        "count": len(scores),
        "mean": np.mean(scores),
        "std": np.std(scores),
        "min": p[0],
        "1%": p[1],
        "5%": p[2],
        "10%": p[3],
        "25%": p[4],
        "50%": p[5],
        "75%": p[6],
        "90%": p[7],
        "95%": p[8],
        "99%": p[9],
        "max": p[10]
    })



# test the Isolation Forest model
test_modular_conn()






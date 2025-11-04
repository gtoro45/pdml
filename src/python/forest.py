# random forest training and usage program for outlier detection
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from encoding import *
import matplotlib.pyplot as plt

# specify the paths
conn_paths = [
    "../../benign_1_min/node-1-child-3/csv files/node1_conn.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_conn.csv",
    "../../benign_1_min/cam-pod/csv files/camera_conn.csv",
    "../../benign_1_min/lidar-pod/csv files/lidar_conn.csv",
    "../../benign_1_min/nginx-pod/csv files/NGINX_conn.csv",
    "../../benign_sim/csv/conn.csv",                                          # benign
    "../../ddos_sim/csv/conn_malignant1.csv"                                  # malignant
]

dns_paths = [
    "../../benign_1_min/node-1-child-3/csv files/node1_dns.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_dns.csv",
    "../../benign_1_min/nginx-pod/csv files/NGINX_dns.csv",
    "../../benign_sim/csv/dns.csv",                                          # benign
    "../../ddos_sim/csv/dns_malignant1.csv"                                  # malignant
]

ssl_paths = [
    "../../benign_1_min/node-1-child-3/csv files/node1_ssl.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_ssl.csv"
]

http_paths = [
    "../../benign_1_min/node-1-child-3/csv files/node1_http.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_http.csv"
]

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
        scaler = StandardScaler()
        X, encoder = encode_training_data(train_path, fit_encoder=True)
        # X_scaled = scaler.fit_transform(X)                                  # fit transform for training

        # scale the training data

        # initialize the isolation forest
        iso_forest = IsolationForest(
            n_estimators=500,
            contamination=0.02, # maximum provided in FSR
            random_state=42
        )

        # train the model
        iso_forest.fit(X)
        # iso_forest.fit(X_scaled)
        
        # test the model on all the sets
        for j in range(len(paths)):
            test_path = paths[j]
            if(i is not j) and (j < 3):
                print(f"Test set: {test_path}")
            elif j == 3:
                print(f"Test set: {test_path} \t <-- BENIGN")
            elif j == 4:
                print(f"Test set: {test_path} \t <-- MALIGNANT")
            else:
                print(f"Test set: {test_path} \t\t\t <-- same as training data")

            # prepare the test data
            df_test = pd.read_csv(test_path)
            X_test = encode_training_data_dns(test_path, encoder=encoder, fit_encoder=False)[0]
            # X_test_scaled = scaler.transform(X_test)                      # transform for testing

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

# encode and scale training data
scaler = StandardScaler()
X, encoder = encode_training_data(conn_paths[0], fit_encoder=True)
X = scaler.fit_transform(X)

# initialize the isolation forest
iso_forest = IsolationForest(
    n_estimators=500,
    contamination=0.02, # maximum provided in FSR
    random_state=42
)

# train the model
iso_forest.fit(X)

# encode test data
X_train, _ = encode_training_data_conn(conn_paths[0], encoder=encoder, fit_encoder=False)
X_live, _ = encode_training_data_conn(conn_paths[5], encoder=encoder, fit_encoder=False)
X_ddos, _ = encode_training_data_conn(conn_paths[6], encoder=encoder, fit_encoder=False)

# scale test data
X_train = scaler.transform(X_train)
X_live = scaler.transform(X_live)
X_ddos = scaler.transform(X_ddos)

# run the model on test data
y_train = iso_forest.predict(X_train)
y_live = iso_forest.predict(X_live)
y_ddos = iso_forest.predict(X_ddos)

scores_train = iso_forest.decision_function(X_train)
scores_live  = iso_forest.decision_function(X_live)
scores_ddos  = iso_forest.decision_function(X_ddos)

# analyze output
s_train = stats("train", scores_train)
s_live  = stats("live",  scores_live)
s_ddos  = stats("ddos",  scores_ddos)

for pct in [0.1, 0.5, 1, 2, 5, 10]:
    thresh = np.percentile(scores_train, pct)
    r_train = (scores_train < thresh).mean()
    r_live  = (scores_live  < thresh).mean()
    r_ddos  = (scores_ddos  < thresh).mean()
    print(f"pct={pct:>4}% | thresh={thresh:.6f} | train={r_train:.4%} | live={r_live:.4%} | ddos={r_ddos:.4%}")


print(pd.DataFrame([s_train, s_live, s_ddos]).set_index("name").T)

# plot the decision functions and compute threshold (2% lowest scores)
threshold = np.percentile(scores_train, 2)  # since contamination = 0.02
print(f"Isolation Forest anomaly threshold (2% cutoff): {threshold:.5f}")
fig, axes = plt.subplots(3, 1, figsize=(10, 8), sharex=True)

# 1 — training (benign)
axes[0].hist(scores_train, bins=200, color='tab:blue', alpha=0.6)
axes[0].axvline(threshold, color='black', linestyle='--', label=f'Threshold = {threshold:.3f}')
axes[0].set_title("Train (benign)")
axes[0].set_yscale('log')
axes[0].legend()
axes[0].grid(True, linestyle='--', alpha=0.3)

# 2 — live 30-min
axes[1].hist(scores_live, bins=200, color='tab:orange', alpha=0.6)
axes[1].axvline(threshold, color='black', linestyle='--')
axes[1].set_title("Live 30-min capture")
axes[1].set_yscale('log')
axes[1].grid(True, linestyle='--', alpha=0.3)

# 3 — DDoS simulation
axes[2].hist(scores_ddos, bins=200, color='tab:red', alpha=0.6)
axes[2].axvline(threshold, color='black', linestyle='--')
axes[2].set_title("DDoS simulation")
axes[2].set_yscale('log')
axes[2].grid(True, linestyle='--', alpha=0.3)

# shared x-axis label
plt.xlabel("Decision function score (higher = more normal)")
plt.tight_layout()
plt.show()



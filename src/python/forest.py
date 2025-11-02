# random forest training and usage program for outlier detection
import pandas as pd
from sklearn.ensemble import IsolationForest
from encoding import *

# specify the paths
conn_paths = [
    "../../benign_1_min/node-1-child-3/csv files/node1_conn.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_conn.csv",
    "../../benign_1_min/cam-pod/csv files/camera_conn.csv",
    "../../benign_1_min/lidar-pod/csv files/lidar_conn.csv",
    "../../benign_1_min/nginx-pod/csv files/NGINX_conn.csv"
]

dns_paths = [
    "../../benign_1_min/node-1-child-3/csv files/node1_dns.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_dns.csv",
    "../../benign_1_min/nginx-pod/csv files/NGINX_dns.csv"
]

ssl_paths = [
    "../../benign_1_min/node-1-child-3/csv files/node1_ssl.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_ssl.csv"
]

http_paths = [
    "../../benign_1_min/node-1-child-3/csv files/node1_http.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_http.csv"
]

# train on 1 of the 5 data sets, and test on the remaining 4
# do this to see relative strength of training sets
paths = dns_paths
for i in range(len(paths)):
    train_path = paths[i]
    print("************************************************************************")
    print(f"Model Trained with [{train_path}]")
    print("************************************************************************\n")
    # prepare the training data, encoder, and frequency mappings
    X, encoder = encode_training_data(train_path, fit_encoder=True)

    # initialize the isolation forest
    iso_forest = IsolationForest(
        n_estimators=100,
        contamination=0.001,
        random_state=42
    )

    # train the model
    iso_forest.fit(X)
    
    # test the model on all the sets
    for j in range(len(paths)):
        test_path = paths[j]
        if(i is not j):
            print(f"Test set: {test_path}")
        else:
            print(f"Test set: {test_path} \t <-- same as training data")

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
        false_positives = (y_pred == -1).sum()
        total = len(y_pred)
        print(f"Total benign test samples: {total}")
        print(f"False positives: {false_positives}")
        print(f"False positive rate: {false_positives / total:.4%}\n")
    print("************************************************************************\n")




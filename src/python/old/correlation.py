import numpy as np
from numpy.linalg import inv
from scipy.stats import chi2
from sklearn.covariance import LedoitWolf
from encoding import *

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

dns_paths = [
    "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_dns.csv",
    "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_dns.csv",
    "../../train_test_data/benign_1_min/nginx-pod/csv files/NGINX_dns.csv",
    "../../train_test_data/benign_sim/csv/dns.csv",                                          # benign
    "../../train_test_data/ddos_sim/csv/dns_malignant1.csv"                                  # malignant
]

ssl_paths = [
    "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_ssl.csv",
    "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_ssl.csv"
]

http_paths = [
    "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_http.csv",
    "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_http.csv"
]

# distance function
def mahalanobis_distance(x, mu, inv_cov):
    diff = x - mu
    return np.sqrt(diff.T @ inv_cov @ diff)

# set up test and training paths
train_path = conn_paths[0]
test_path = conn_paths[6]

# train the matrix
X, encoder = encode_training_data(train_path, fit_encoder=True)

# Compute mean vector, covariance matrix, and correlation matrix
cov_estimator = LedoitWolf().fit(X)
mu_vec = cov_estimator.location_
cov_matrix = cov_estimator.covariance_

# compute the inverse matrix and mean matrix for mahalanobis distance
inv_cov = inv(cov_matrix)

# encode the test set
X_test, _ = encode_training_data(test_path, encoder=encoder, fit_encoder=False)
X_test = X_test[X.columns]

# compute the test set's distance from matrix [Vectorized Mahalanobis distance]
diff = X_test.values - mu_vec
left = diff @ inv_cov
md_squared = np.sum(left * diff, axis=1)
md = np.sqrt(md_squared)

# make determinations about the test set
k = len(mu_vec)
threshold = np.sqrt(chi2.ppf(0.997, df=k))  # ~3σ equivalent
anomalies = md > threshold
X_test["mahalanobis"] = md
X_test["is_anomaly"] = anomalies

# Evaluate test results
if 'malignant' not in test_path:
    false_positives = X_test["is_anomaly"].sum()
    total = len(X_test)
    print(f"Total benign test samples: {total}")
    print(f"False positives: {false_positives}")
    print(f"False positive rate: {false_positives / total:.4%}\n")

else:
    flagged_transactions = X_test["is_anomaly"].sum()
    total_transactions = len(X_test)
    print(f"Total test samples: {total_transactions}")
    print(f"Number of flagged transactions: {flagged_transactions}")
    print(f"Detection rate: {flagged_transactions / total_transactions:.4%}")


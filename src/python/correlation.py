import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from encoding import *

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
paths = conn_paths

for path in paths:
    print("****************************************************************************************************")
    print(path)
    df_numeric, _ = encode_training_data_conn(path, fit_encoder=True)

    # Compute mean vector, covariance matrix, and correlation matrix
    mu = df_numeric.mean()
    cov_matrix = df_numeric.cov(min_periods=1)
    corr_matrix = df_numeric.corr(min_periods=1)

    print(corr_matrix)
    print("****************************************************************************************************\n")

    # Plot them
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    
    # Mean vector (bar chart)
    axes[0].bar(mu.index, mu.values)
    axes[0].set_title("Mean Vector (μ)")
    axes[0].set_xticklabels(mu.index, rotation=90)

    # Covariance matrix
    sns.heatmap(cov_matrix, ax=axes[1], cmap="coolwarm", cbar=True, center=0)
    axes[1].set_title("Covariance Matrix (Σ)")

    # Correlation matrix
    sns.heatmap(corr_matrix, ax=axes[2], cmap="coolwarm", cbar=True, center=0) #, annot=True, fmt=".2f")
    axes[2].set_title("Correlation Matrix (R)")
    axes[2].xaxis.set_ticks_position('bottom')
    axes[2].xaxis.set_label_position('bottom')

    plt.tight_layout()
    plt.show()
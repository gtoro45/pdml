import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

def get_column_names(logfile_type):
    """
    Returns the column names corresponding to the indices for each log type.
    Useful for creating DataFrames with proper column names.
    
    Parameters:
    -----------
    logfile_type : str
        Type of log file ('CONN', 'DNS', 'HTTP', 'SSL', 'WEIRD', 'UNKNOWN')
    
    Returns:
    --------
    list or None : List of column names, or None for UNKNOWN type
    """
    
    logfile_type = logfile_type.upper()
    
    if logfile_type == 'CONN':
        return ['ts', 'uid', 'id.orig_h', 'id.resp_h', 'proto', 'duration', 
                'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 
                'local_resp', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 
                'resp_ip_bytes']
    
    elif logfile_type == 'DNS':
        return ['ts', 'uid', 'id.orig_h', 'id.resp_h', 'proto', 'rtt', 
                'query', 'qtype', 'qtype_name', 'rcode', 'rcode_name', 'answers', 'TTLs']
    
    elif logfile_type == 'HTTP':
        return ['ts', 'uid', 'id.orig_h', 'id.resp_h', 'method', 'host', 
                'uri', 'referrer', 'user_agent', 'request_body_len', 
                'response_body_len', 'status_code', 'resp_mime_types', 
                'resp_fuids', 'orig_fuids', 'orig_filenames', 'resp_filenames', 
                'trans_depth']
    
    elif logfile_type == 'SSL':
        return ['ts', 'uid', 'id.orig_h', 'id.resp_h', 'cipher', 
                'curve', 'server_name', 'ssl_history']
    
    elif logfile_type == 'WEIRD':
        return ['ts', 'uid', 'id.orig_h', 'id.resp_h', 'name', 'addl', 
                'notice', 'peer', 'source']
    
    elif logfile_type == 'UNKNOWN':
        return None
    
    else:
        return []
    
def get_logtype(path):
    if 'conn' in path: return 'CONN'
    if 'dns' in path: return 'DNS'
    if 'http' in path: return 'HTTP'
    if 'ssl' in path: return 'SSL'
    if 'weird' in path: return 'WEIRD'
    return 'UNKNOWN'

# Load the Zeek datasets
paths = [
    # Node 1 (Child 3)
    "../benign_1_min/Node 1 (Child 3)/csv files/node1_conn.csv",
    "../benign_1_min/Node 1 (Child 3)/csv files/node1_dns.csv",
    "../benign_1_min/Node 1 (Child 3)/csv files/node1_http.csv",
    "../benign_1_min/Node 1 (Child 3)/csv files/node1_ssl.csv",
    
    # Node 2 (Child 4)
    "../benign_1_min/Node 2 (Child 4)/csv files/node2_conn.csv",
    "../benign_1_min/Node 2 (Child 4)/csv files/node2_dns.csv",
    "../benign_1_min/Node 2 (Child 4)/csv files/node2_http.csv",
    "../benign_1_min/Node 2 (Child 4)/csv files/node2_ssl.csv",
    
    # Camera Pod
    "../benign_1_min/Camera Pod/csv files/camera_conn.csv",
    
    # LiDAR Pod
    "../benign_1_min/LiDAR Pod/csv files/lidar_conn.csv",
    
    # NGINX Pod
    "../benign_1_min/NGINX Pod/csv files/NGINX_conn.csv",
    "../benign_1_min/NGINX Pod/csv files/NGINX_dns.csv"
]

for path in paths:
    print("****************************************************************************************************")
    print(path)
    columns = get_column_names(get_logtype(path))
    df = pd.read_csv(path, na_values=['-'])[columns]

    # Select only numeric columns
    df_numeric = df.select_dtypes(include=[np.number]) 
    print(df_numeric)

    # Compute mean vector, covariance matrix, and correlation matrix
    mu = df_numeric.mean()
    cov_matrix = df_numeric.cov(min_periods=1)
    corr_matrix = df_numeric.corr(min_periods=1)

    print(corr_matrix)
    print("****************************************************************************************************\n")

# # Plot them
# fig, axes = plt.subplots(1, 3, figsize=(18, 5))

# # Mean vector (bar chart)
# axes[0].bar(mu.index, mu.values)
# axes[0].set_title("Mean Vector (μ)")
# axes[0].set_xticklabels(mu.index, rotation=90)

# # Covariance matrix
# sns.heatmap(cov_matrix, ax=axes[1], cmap="coolwarm", cbar=True, center=0)
# axes[1].set_title("Covariance Matrix (Σ)")

# # Correlation matrix
# sns.heatmap(corr_matrix, ax=axes[2], cmap="coolwarm", cbar=True, center=0)
# axes[2].set_title("Correlation Matrix (R)")
# axes[2].xaxis.set_ticks_position('bottom')
# axes[2].xaxis.set_label_position('bottom')

# plt.tight_layout()
# plt.show()
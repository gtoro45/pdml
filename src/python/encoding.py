# encode Zeek csvs into readable data for random forest model
import numpy as np
import pandas as pd 
from sklearn.preprocessing import OneHotEncoder, StandardScaler

def encode_training_data(path, encoder=None, fit_encoder=True):
    """
    Helper function that calls the appropriate encoder based on the file type specified by path

    Parameters:
        - path (str): Path to training data
        - encoder (OneHotEncoder, optional): The encoder to be used post-training. Should be the same as the training encoder. Defaults to None.
        - fit_encoder (bool, optional): True for training, False for testing. Defaults to True.
        
    Returns:
        - [0]: df (pd.DataFrame): Encoded numeric dataframe ready for model training or inference.
        - [1]: encoder (OneHotEncoder): The fitted or reused encoder object.
    """
    if 'conn' in path: 
        return encode_training_data_conn(conn_path=path, encoder=encoder, fit_encoder=fit_encoder)
    elif 'dns' in path: 
        return encode_training_data_dns(dns_path=path, encoder=encoder, fit_encoder=fit_encoder)
    elif 'ssl' in path: 
        return encode_training_data_ssl(ssl_path=path, encoder=encoder, fit_encoder=fit_encoder)
    elif 'http' in path: 
        return encode_training_data_http(http_path=path, encoder=encoder, fit_encoder=fit_encoder)
    else:
        raise ValueError(f"Unrecognized log type in path: {path}")

# ========================
# conn.log field types 
# ========================
# ts                : time          [X]
# uid               : string        [X]
# id.orig_h         : addr          [X]
# id.orig_p         : port          [X]
# id.resp_h         : addr          [X]
# id.resp_p         : port          [X]
# proto             : enum
# service           : string
# duration          : interval
# orig_bytes        : count
# resp_bytes        : count
# conn_state        : string
# local_orig        : bool
# local_resp        : bool
# missed_bytes      : count
# history           : string
# orig_pkts         : count
# orig_ip_bytes     : count
# resp_pkts         : count
# resp_ip_bytes     : count
# tunnel_parents    : set[string]   [X]
# ip_proto          : count         [X]
def encode_training_data_conn(conn_path, encoder=None, fit_encoder=True):
    """
    Function that encodes training conn.log data, doing so file by file. Encoding and ensuing training
    is done **without** the following, and are better handled by separate logic:
        - ts                : Timestamp of the connection
        - uid               : Unique connection identifier
        - id.orig_h         : Origin host IP address
        - id.resp_h         : Responding host IP address
        - id.orig_p         : Origin port number
        - id.resp_p         : Responding port number
        - tunnel_parents    : Encapsulation or parent tunnel info (rarely useful)
        - ip_proto          : Numeric IP protocol (redundant with 'proto')
    
    Parameters:
        - conn_path (str): Path to the CSV file containing connection logs.
        - encoder (OneHotEncoder, optional): Reused encoder for consistent categorical encoding.
        - fit_encoder (bool): Whether to fit a new encoder or reuse an existing one.

    Returns:
        - [0]: df (pd.DataFrame): Encoded numeric dataframe ready for model training or inference.
        - [1]: encoder (OneHotEncoder): The fitted or reused encoder object.
    """
    
    # read the csv and place it into a dataframe
    # exclude the columns specified in the function header
    df = pd.read_csv(conn_path)
    df = df.drop(
        ['ts', 'uid', 'id.orig_h', 
         'id.resp_h', 'id.orig_p', 
         'id.resp_p', 'tunnel_parents', 
         'ip_proto'], 
        axis='columns', 
        errors='ignore'
    )
    
    # handle missing symbols
    df.replace('-', pd.NA, inplace=True)
    
    # handle missing categorical values as unknown instead of dropping/zeroing (history handled separately)
    df['proto'] = df['proto'].fillna('unknown')
    df['service'] = df['service'].fillna('unknown')
    df['conn_state'] = df['conn_state'].fillna('unknown')
    
    # handle missing numeric values with a missing indicator column
    num_cols_with_na = ['duration', 'orig_bytes', 'resp_bytes', 'missed_bytes', 
                        'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']
    for col in num_cols_with_na:
        if col in df.columns:
            df[f"{col}_missing"] = df[col].isna().astype(int)
            # median_val = df[col].median()
            # df[col] = pd.to_numeric(df[col], errors='coerce').fillna(median_val)
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    # handle booleans
    df['local_orig'] = df['local_orig'].map({'T' : 1, 'F' : 0, pd.NA : 0})
    df['local_resp'] = df['local_resp'].map({'T' : 1, 'F' : 0, pd.NA : 0})
    
    # encode history from derived features
    df['hist_len'] = df['history'].astype(str).apply(lambda x: 0 if x in ['<NA>', 'nan', 'None'] else len(x))               # length of this history string
    df['hist_upper'] = df['history'].astype(str).apply(lambda x: sum(c.isupper() for c in x))                               # number of capital letters in history string
    df['hist_unique'] = df['history'].astype(str).apply(lambda x: len(set(x)) if x not in ['<NA>', 'nan', 'None'] else 0)   # number of unique letters in history string
    df.drop(columns=['history'], inplace=True)
    
    # one-hot encode small categorical columns
    cat_cols = ['proto', 'service', 'conn_state']
    if fit_encoder or encoder is None:
        encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        encoded = encoder.fit_transform(df[cat_cols])
    else:
        encoded = encoder.transform(df[cat_cols])
    encoded_df = pd.DataFrame(encoded, columns=encoder.get_feature_names_out(cat_cols), index=df.index)
    df = pd.concat([df.drop(columns=cat_cols), encoded_df], axis=1)
    
    # return
    return df, encoder

# ========================
# dns.log field types
# ========================
# ts            : time                  [X]
# uid           : string                [X]
# id.orig_h     : addr                  [X]
# id.orig_p     : port                  [X]
# id.resp_h     : addr                  [X]
# id.resp_p     : port                  [X]
# proto         : enum
# trans_id      : count                 [X]
# rtt           : interval
# query         : string                [X]
# qclass        : count
# qclass_name   : string
# qtype         : count
# qtype_name    : string
# rcode         : count
# rcode_name    : string
# AA            : bool
# TC            : bool
# RD            : bool
# RA            : bool
# Z             : count
# answers       : vector[string]
# TTLs          : vector[interval]
# rejected      : bool
def encode_training_data_dns(dns_path, encoder=None, fit_encoder=True):
    """
    Function that encodes training dns.log data, doing so file by file. Encoding and ensuing training
    is done **without** the following, and are better handled by separate logic:
        - ts                : Timestamp of the connection
        - uid               : Unique connection identifier
        - id.orig_h         : Origin host IP address
        - id.resp_h         : Responding host IP address
        - id.orig_p         : Origin port number
        - id.resp_p         : Responding port number
        - trans_id          : Identifier assigned by the program that generated the DNS query
        - query             : The domain name that is the subject of the DNS query (will be handled by LUT)
    
    Parameters:
        - dns_path (str): Path to the CSV file containing dns logs.
        - encoder (OneHotEncoder, optional): Reused encoder for consistent categorical encoding.
        - fit_encoder (bool): Whether to fit a new encoder or reuse an existing one.

    Returns:
        - [0]: df (pd.DataFrame): Encoded numeric dataframe ready for model training or inference.
        - [1]: encoder (OneHotEncoder): The fitted or reused encoder object.
    """
    
    # read the csv and place it into a dataframe
    # exclude the columns specified in the function header
    df = pd.read_csv(dns_path)
    df = df.drop(
        # leaves us with: proto, rtt, qclass, qclass_name, qtype, qtype_name, rcode, rcode_name, AA, TC, RD, RA, Z, answers, TTLs, rejected
        ['ts', 'uid', 'id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'trans_id', 'query'], 
        axis='columns', 
        errors='ignore'
    )
    
    # handle missing symbols
    df.replace('-', pd.NA, inplace=True)
    
    # handle missing categorical values as unknown instead of dropping/zeroing (answers and TTLs handled separately)
    df['proto'] = df['proto'].fillna('unknown')
    df['qclass_name'] = df['qclass_name'].fillna('unknown')
    df['qtype_name'] = df['qtype_name'].fillna('unknown')
    df['rcode_name'] = df['rcode_name'].fillna('unknown')
    
    # handle missing numeric values with a missing indicator column
    num_cols_with_na = ['rtt', 'qclass', 'qtype', 'rcode', 'Z']
    for col in num_cols_with_na:
        if col in df.columns:
            df[f"{col}_missing"] = df[col].isna().astype(int)
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    # handle booleans
    df['AA'] = df['AA'].map({'T' : 1, 'F' : 0, pd.NA : 0})
    df['TC'] = df['TC'].map({'T' : 1, 'F' : 0, pd.NA : 0})
    df['RD'] = df['RD'].map({'T' : 1, 'F' : 0, pd.NA : 0})
    df['RA'] = df['RA'].map({'T' : 1, 'F' : 0, pd.NA : 0})
    df['rejected'] = df['rejected'].map({'T' : 1, 'F' : 0, pd.NA : 0})
    
    # one-hot encode categorical columns
    cat_cols = ['proto', 'qclass_name', 'qtype_name', 'rcode_name']
    if fit_encoder or encoder is None:
        encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        encoded = encoder.fit_transform(df[cat_cols])
    else:
        encoded = encoder.transform(df[cat_cols])
    encoded_df = pd.DataFrame(encoded, columns=encoder.get_feature_names_out(cat_cols), index=df.index)
    df = pd.concat([df.drop(columns=cat_cols), encoded_df], axis=1)
    
    # handle answers
    df['answers_count'] = df['answers'].astype(str).apply(lambda x: 0 if x in ['-', 'nan', '<NA>'] else len(x.split(',')))
    df['answers_unique_count'] = df['answers'].astype(str).apply(lambda x: len(set(x.split(','))) if x not in ['-', 'nan', '<NA>'] else 0)
    df['answers_has_ipv6'] = df['answers'].astype(str).apply(lambda x: any(':' in a for a in x.split(',')) if x not in ['-', 'nan', '<NA>'] else 0)
    df.drop(columns=['answers'], inplace=True)
    
    # handle TTLs
    df['ttls_mean'] = df['TTLs'].astype(str).apply(lambda x: np.mean([float(t) for t in x.split(',')]) if x not in ['-', 'nan', '<NA>'] else 0)
    df['ttls_std'] = df['TTLs'].astype(str).apply(lambda x: np.std([float(t) for t in x.split(',')]) if x not in ['-', 'nan', '<NA>'] else 0)
    df['ttls_count'] = df['TTLs'].astype(str).apply(lambda x: 0 if x in ['-', 'nan', '<NA>'] else len(x.split(',')))
    df.drop(columns=['TTLs'], inplace=True)
    
    # add a ttl-answer mismatch column (len(ttl) == len(answers) in all benign data, be explicit)
    df['answers_ttls_mismatch'] = (df['answers_count'] != df['ttls_count']).astype(int)
    
    # convert all remaining columns to numeric
    # handles ['rtt', 'qclass', 'qtype', 'rcode', 'Z']
    for c in df.columns:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
    
    # print("************************************************************************")
    # print(df)
    # print("************************************************************************\n")
    return df, encoder

# ========================
# ssl.log field types
# ========================
# ts                     : time
# uid                    : string
# id.orig_h              : addr
# id.orig_p              : port
# id.resp_h              : addr
# id.resp_p              : port
# version                : string
# cipher                 : string
# curve                  : string
# server_name            : string
# resumed                : bool
# last_alert             : string
# next_protocol          : string
# established            : bool
# ssl_history            : string
# cert_chain_fps         : vector[string]
# client_cert_chain_fps  : vector[string]
# sni_matches_cert       : bool
def encode_training_data_ssl(ssl_path, encoder=None, fit_encoder=True):
    
    # read the csv and place it into a dataframe
    # exclude the columns specified in the function header
    df = pd.read_csv(ssl_path)
    
    return df, encoder

# ========================
# http.log field types
# ========================
# ts                 : time
# uid                : string
# id.orig_h          : addr
# id.orig_p          : port
# id.resp_h          : addr
# id.resp_p          : port
# trans_depth        : count
# method             : string
# host               : string
# uri                : string
# referrer           : string
# version            : string
# user_agent         : string
# origin             : string
# request_body_len   : count
# response_body_len  : count
# status_code        : count
# status_msg         : string
# info_code          : count
# info_msg           : string
# tags               : set[enum]
# username           : string
# password           : string
# proxied            : set[string]
# orig_fuids         : vector[string]
# orig_filenames     : vector[string]
# orig_mime_types    : vector[string]
# resp_fuids         : vector[string]
# resp_filenames     : vector[string]
# resp_mime_types    : vector[string]
def encode_training_data_http(http_path, encoder=None, fit_encoder=True):
    
    # read the csv and place it into a dataframe
    # exclude the columns specified in the function header
    df = pd.read_csv(http_path)
    
    return df, encoder

# TODO
def encode_live_data_conn(csv_line):
    """
    Function that encodes test data, doing so line by line
    """
    return


paths = [ 
    # Node 1 (Child 3)
    "../../benign_1_min/node-1-child-3/csv files/node1_conn.csv",
    "../../benign_1_min/node-1-child-3/csv files/node1_dns.csv",
    "../../benign_1_min/node-1-child-3/csv files/node1_http.csv",
    "../../benign_1_min/node-1-child-3/csv files/node1_ssl.csv",
    
    # Node 2 (Child 4)
    "../../benign_1_min/node-2-child-4/csv files/node2_conn.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_dns.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_http.csv",
    "../../benign_1_min/node-2-child-4/csv files/node2_ssl.csv",
    
    # Camera Pod
    "../../benign_1_min/cam-pod/csv files/camera_conn.csv",
    
    # LiDAR Pod
    "../../benign_1_min/lidar-pod/csv files/lidar_conn.csv",
    
    # NGINX Pod
    "../../benign_1_min/nginx-pod/csv files/NGINX_conn.csv",
    "../../benign_1_min/nginx-pod/csv files/NGINX_dns.csv"
]
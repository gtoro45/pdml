import numpy as np
import pandas as pd
from scipy.fft import rfft, rfftfreq
import matplotlib.pyplot as plt
from rules_extract import print_dict
from collections import deque
import pywt
from scipy.stats import entropy as scipy_entropy



# conn.log specific ffts
def fft_timestamps_per_sec_conn(window_df):
    # sort the df by timestamp
    window_df = window_df.sort_values(by="ts")
    
    # Convert timestamps to per-second counts
    # ts = pd.to_datetime(window_df[ts_col], unit='s')
    # counts = ts.dt.floor("1s").value_counts().sort_index()
    # y = counts.values.astype(float)
    
    # calculate inter-arrrival times
    timestamps = pd.to_numeric(window_df['ts'])
    y = np.diff(timestamps)
    
    # apply the hanning transform (?)
    # y = y * np.hanning(len(y))   

    if len(y) < 4:
        return {"fft_energy":0, "fft_entropy":0, "dominant_freq":0, "hf_lf_ratio":0}

    Y = np.abs(rfft(y))
    freqs = rfftfreq(len(y), d=1.0)

    # Avoid DC component
    Y_no_dc = Y[1:]

    # Spectral features (energy)
    energy = np.sum(Y_no_dc**2)
    p = Y_no_dc / (np.sum(Y_no_dc) + 1e-12)
    entropy = -np.sum(p * np.log(p + 1e-12))
    dominant_freq = freqs[1:][np.argmax(Y_no_dc)]
    
    # Spectral features (power)
    # P = (np.abs(rfft(y))**2)[1:] # remove DC
    # p = P / (P.sum() + 1e-12)
    # entropy = -np.sum(p * np.log(p + 1e-12))

    # high-frequency / low-frequency ratio
    split = len(Y_no_dc)//2
    hf_lf_ratio = (np.sum(Y_no_dc[split:]) + 1e-9) / (np.sum(Y_no_dc[:split]) + 1e-9)

    return {
        "fft_energy": float(energy),
        "fft_entropy": float(entropy),
        "dominant_freq": float(dominant_freq),
        "hf_lf_ratio": float(hf_lf_ratio)
    }

def fft_bytes_per_sec_conn(window_df, orig_bytes="orig_bytes", resp_bytes="resp_bytes", ts_col="ts"):
    # sort the df by timestamp
    window_df = window_df.sort_values(by="ts")
    
    # Combine byte directions
    total_bytes = window_df[orig_bytes].fillna(0) + window_df[resp_bytes].fillna(0)

    # Aggregate by second
    ts = pd.to_datetime(window_df[ts_col], unit='s')
    per_sec = total_bytes.groupby(ts.dt.floor("1s")).sum().sort_index()
    y = per_sec.values.astype(float)
    # y = y * np.hanning(len(y))  # hanning transform 

    if len(y) < 4:
        return {"fft_energy":0, "fft_entropy":0, "dominant_freq":0, "hf_lf_ratio":0}

    Y = np.abs(rfft(y))
    freqs = rfftfreq(len(y), d=1)

    Y_no_dc = Y[1:]
    energy = np.sum(Y_no_dc**2)
    p = Y_no_dc / (np.sum(Y_no_dc) + 1e-12)
    entropy = -np.sum(p * np.log(p + 1e-12))
    dominant_freq = freqs[1:][np.argmax(Y_no_dc)]
    
    # Spectral features (power)
    # P = (np.abs(rfft(y))**2)[1:] # remove DC
    # p = P / (P.sum() + 1e-12)
    # entropy = -np.sum(p * np.log(p + 1e-12))

    split = len(Y_no_dc)//2
    hf_lf_ratio = (np.sum(Y_no_dc[split:]) + 1e-9) / (np.sum(Y_no_dc[:split]) + 1e-9)

    return {
        "fft_energy": float(energy),
        "fft_entropy": float(entropy),
        "dominant_freq": float(dominant_freq),
        "hf_lf_ratio": float(hf_lf_ratio)
    }

def fft_packets_per_sec_conn(window_df, orig_pkts="orig_pkts", resp_pkts="resp_pkts", ts_col="ts"):
    # sort the df by timestamp
    window_df = window_df.sort_values(by="ts")
    
    total_pkts = window_df[orig_pkts].fillna(0) + window_df[resp_pkts].fillna(0)

    ts = pd.to_datetime(window_df[ts_col], unit='s')
    per_sec = total_pkts.groupby(ts.dt.floor("1s")).sum().sort_index()
    y = per_sec.values.astype(float)
    # y = y * np.hanning(len(y))  # hanning transform 

    if len(y) < 4:
        return {"fft_energy":0, "fft_entropy":0, "dominant_freq":0, "hf_lf_ratio":0}

    Y = np.abs(rfft(y))
    freqs = rfftfreq(len(y), d=1)

    Y_no_dc = Y[1:]
    energy = np.sum(Y_no_dc**2)
    p = Y_no_dc / (np.sum(Y_no_dc) + 1e-12)
    entropy = -np.sum(p * np.log(p + 1e-12))
    dominant_freq = freqs[1:][np.argmax(Y_no_dc)]
    
    # Spectral features (power)
    # P = (np.abs(rfft(y))**2)[1:] # remove DC
    # p = P / (P.sum() + 1e-12)
    # entropy = -np.sum(p * np.log(p + 1e-12))

    split = len(Y_no_dc)//2
    hf_lf_ratio = (np.sum(Y_no_dc[split:]) + 1e-9) / (np.sum(Y_no_dc[:split]) + 1e-9)

    return {
        "fft_energy": float(energy),
        "fft_entropy": float(entropy),
        "dominant_freq": float(dominant_freq),
        "hf_lf_ratio": float(hf_lf_ratio)
    }

def fft_conncount_per_sec_conn(window_df, ts_col="ts"):
    # sort the df by timestamp
    window_df = window_df.sort_values(by="ts")
    
    ts = pd.to_datetime(window_df[ts_col], unit='s')
    per_sec = ts.dt.floor("1s").value_counts().sort_index()
    y = per_sec.values.astype(float)
    # y = y * np.hanning(len(y))  # hanning transform 

    if len(y) < 4:
        return {"fft_energy":0, "fft_entropy":0, "dominant_freq":0, "hf_lf_ratio":0}

    Y = np.abs(rfft(y))
    freqs = rfftfreq(len(y), d=1)

    Y_no_dc = Y[1:]
    energy = np.sum(Y_no_dc**2)
    p = Y_no_dc / (np.sum(Y_no_dc) + 1e-12)
    entropy = -np.sum(p * np.log(p + 1e-12))
    dominant_freq = freqs[1:][np.argmax(Y_no_dc)]
    
    # Spectral features (power)
    # P = (np.abs(rfft(y))**2)[1:] # remove DC
    # p = P / (P.sum() + 1e-12)
    # entropy = -np.sum(p * np.log(p + 1e-12))

    split = len(Y_no_dc)//2
    hf_lf_ratio = (np.sum(Y_no_dc[split:]) + 1e-9) / (np.sum(Y_no_dc[:split]) + 1e-9)

    return {
        "fft_energy": float(energy),
        "fft_entropy": float(entropy),
        "dominant_freq": float(dominant_freq),
        "hf_lf_ratio": float(hf_lf_ratio)
    }


def raw_fft_timestamps_per_sec_conn(df):
    df["_ts_sec"] = df["ts"].astype(float).astype(int)
    per_sec = df.groupby("_ts_sec").size()
    y = per_sec.values.astype(float)
    spectrum = np.abs(np.fft.rfft(y))
    return spectrum

def raw_fft_bytes_per_sec_conn(df):
    df["_ts_sec"] = df["ts"].astype(float).astype(int)

    # Clean bytes fields
    a = pd.to_numeric(df["orig_bytes"], errors="coerce").fillna(0)
    b = pd.to_numeric(df["resp_bytes"], errors="coerce").fillna(0)
    df["_bytes"] = a + b

    per_sec = df.groupby("_ts_sec")["_bytes"].sum()
    y = per_sec.values.astype(float)
    spectrum = np.abs(np.fft.rfft(y))
    return spectrum

def raw_fft_packets_per_sec_conn(df):
    df["_ts_sec"] = df["ts"].astype(float).astype(int)

    a = pd.to_numeric(df["orig_pkts"], errors="coerce").fillna(0)
    b = pd.to_numeric(df["resp_pkts"], errors="coerce").fillna(0)
    df["_pkts"] = a + b

    per_sec = df.groupby("_ts_sec")["_pkts"].sum()
    y = per_sec.values.astype(float)
    spectrum = np.abs(np.fft.rfft(y))
    return spectrum

def raw_fft_conncount_per_sec_conn(df):
    df["_ts_sec"] = df["ts"].astype(float).astype(int)
    per_sec = df.groupby("_ts_sec").size()
    y = per_sec.values.astype(float)
    spectrum = np.abs(np.fft.rfft(y))
    return spectrum

# ************************************************************* <-- Claude Generated
# def wavelet_analysis(signal, wavelet='morl', max_scale=32):
#     """
#     Continuous Wavelet Transform analysis
#     Returns time-frequency features
#     """
#     if len(signal) < 4:
#         return {
#             'wavelet_energy': 0,
#             'wavelet_entropy': 0,
#             'max_scale': 0,
#             'energy_ratio': 0,
#             'scale_diversity': 0
#         }
    
#     # Continuous Wavelet Transform
#     scales = np.arange(1, min(max_scale, len(signal)//2))
#     if len(scales) == 0:
#         scales = np.array([1])
    
#     coeffs, freqs = pywt.cwt(signal, scales, wavelet)
    
#     # Power spectrum
#     power = np.abs(coeffs)**2
#     total_power = np.sum(power)
    
#     # Normalized power for entropy calculation
#     power_norm = power / (total_power + 1e-12)
    
#     # Calculate entropy across the entire power matrix
#     power_flat = power_norm.flatten()
#     wavelet_entropy = -np.sum(power_flat * np.log(power_flat + 1e-12))
    
#     # Energy per scale
#     scale_energies = np.sum(power, axis=1)
    
#     features = {
#         'wavelet_energy': float(total_power),
#         'wavelet_entropy': float(wavelet_entropy),
#         'max_scale': float(scales[np.argmax(scale_energies)]),  # Dominant scale
#         'energy_ratio': float(np.sum(scale_energies[:len(scales)//2]) / (np.sum(scale_energies[len(scales)//2:]) + 1e-9)),
#         'scale_diversity': float(scipy_entropy(scale_energies + 1e-12))  # Distribution across scales
#     }
    
#     return features

# def wavelet_packet_analysis(signal, wavelet='db4', maxlevel=3):
#     """
#     Wavelet Packet Decomposition for multi-resolution analysis
#     """
#     if len(signal) < 2**maxlevel:
#         return {
#             'wp_entropy': 0,
#             'wp_max_energy_level': 0,
#             'wp_energy_concentration': 0
#         }
    
#     try:
#         wp = pywt.WaveletPacket(data=signal, wavelet=wavelet, mode='symmetric', maxlevel=maxlevel)
        
#         # Get energy at each node in the final level
#         node_energies = []
#         for node in wp.get_level(maxlevel, 'freq'):
#             node_energies.append(np.sum(node.data**2))
        
#         if not node_energies:
#             return {
#                 'wp_entropy': 0,
#                 'wp_max_energy_level': 0,
#                 'wp_energy_concentration': 0
#             }
        
#         return {
#             'wp_entropy': float(scipy_entropy(node_energies + np.array([1e-12]*len(node_energies)))),
#             'wp_max_energy_level': int(np.argmax(node_energies)),
#             'wp_energy_concentration': float(max(node_energies) / (sum(node_energies) + 1e-9))
#         }
#     except:
#         return {
#             'wp_entropy': 0,
#             'wp_max_energy_level': 0,
#             'wp_energy_concentration': 0
#         }

# def wavelet_timestamps_per_sec(window_df, ts_col="ts"):
#     """Wavelet analysis of timestamps per second"""
#     window_df = window_df.sort_values(by=ts_col)
#     ts = pd.to_datetime(window_df[ts_col], unit='s')
#     counts = ts.dt.floor("1s").value_counts().sort_index()
#     y = counts.values.astype(float)
    
#     cwt_feats = wavelet_analysis(y)
#     wp_feats = wavelet_packet_analysis(y)
    
#     return {**cwt_feats, **wp_feats}

# def wavelet_conncount_per_sec(window_df, ts_col="ts"):
#     """Wavelet analysis of connection count per second"""
#     window_df = window_df.sort_values(by=ts_col)
#     ts = pd.to_datetime(window_df[ts_col], unit='s')
#     per_sec = ts.dt.floor("1s").value_counts().sort_index()
#     y = per_sec.values.astype(float)
    
#     cwt_feats = wavelet_analysis(y)
#     wp_feats = wavelet_packet_analysis(y)
    
#     return {**cwt_feats, **wp_feats}

# def extract_fft_ruleset_conn():
#     """
#     Build hybrid ruleset with both FFT and Wavelet stats
#     """
#     conn_paths = [
#         "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",
#         "../../train_test_data/new-benign_10_min/csv/child2/conn.csv",
#         "../../train_test_data/new-benign_10_min/csv/cam-pod/conn.csv",
#         "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv",
#         "../../train_test_data/new-benign_10_min/csv/nginx-pod/conn.csv",
#     ]
    
#     NUMERIC_COLS = ['orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'duration']
    
#     # Wavelet features for temporal patterns
#     timestamp_wavelet_feats = []
#     conn_wavelet_feats = []
    
#     # FFT features for rate patterns
#     bps_fft_feats = []
#     pps_fft_feats = []
    
#     for path in conn_paths:
#         df = pd.read_csv(path)
#         for col in NUMERIC_COLS:
#             df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
#         # Wavelet for timestamps and connections
#         timestamp_wavelet_feats.append(wavelet_timestamps_per_sec(df))
#         conn_wavelet_feats.append(wavelet_conncount_per_sec(df))
        
#         # FFT for bytes and packets
#         bps_fft_feats.append(fft_bytes_per_sec_conn(df))
#         pps_fft_feats.append(fft_packets_per_sec_conn(df))
    
#     result = {
#         'timestamp': _calculate_stats(timestamp_wavelet_feats, 'wavelet'),
#         'bps': _calculate_stats(bps_fft_feats, 'fft'),
#         'pps': _calculate_stats(pps_fft_feats, 'fft'),
#         'conn': _calculate_stats(conn_wavelet_feats, 'wavelet')
#     }
    
#     return result

# def extract_wavelet_ruleset_per_window_size(window_size=500):
#     """
#     Build ruleset using SLIDING WINDOWS of the specified size
#     This matches the scale of your detection windows
#     """
#     conn_paths = [
#         "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",
#         "../../train_test_data/new-benign_10_min/csv/child2/conn.csv",
#         "../../train_test_data/new-benign_10_min/csv/cam-pod/conn.csv",
#         "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv",
#         "../../train_test_data/new-benign_10_min/csv/nginx-pod/conn.csv",
#     ]
    
#     NUMERIC_COLS = ['orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts', 'duration']
    
#     timestamp_wavelet_feats = []
#     bps_fft_feats = []
#     pps_fft_feats = []
#     conn_wavelet_feats = []
    
#     for path in conn_paths:
#         df = pd.read_csv(path)
#         for col in NUMERIC_COLS:
#             df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
#         total_rows = len(df)
#         stride = window_size // 2  # 50% overlap
        
#         # Slide window through the dataset
#         for start in range(0, total_rows - window_size + 1, stride):
#             end = start + window_size
#             win_df = df.iloc[start:end]
            
#             # Extract features from this window
#             timestamp_wavelet_feats.append(wavelet_timestamps_per_sec(win_df))
#             bps_fft_feats.append(fft_bytes_per_sec_conn(win_df))
#             pps_fft_feats.append(fft_packets_per_sec_conn(win_df))
#             conn_wavelet_feats.append(wavelet_conncount_per_sec(win_df))
    
#     result = {
#         'timestamp': _calculate_stats(timestamp_wavelet_feats, 'wavelet'),
#         'bps': _calculate_stats(bps_fft_feats, 'fft'),
#         'pps': _calculate_stats(pps_fft_feats, 'fft'),
#         'conn': _calculate_stats(conn_wavelet_feats, 'wavelet')
#     }
    
#     return result

# def _calculate_stats(feature_list, analysis_type='fft'):
#     """
#     Helper to calculate mean/std for either FFT or wavelet features
#     """
#     if not feature_list:
#         return {}
    
#     stats = {}
    
#     if analysis_type == 'wavelet':
#         metrics = ['wavelet_entropy', 'max_scale', 'energy_ratio', 'scale_diversity']
#     else:  # fft
#         metrics = ['fft_entropy', 'dominant_freq', 'hf_lf_ratio']
    
#     for metric in metrics:
#         vals = [d[metric] for d in feature_list]
#         stats[f'{metric}_mean'] = np.mean(vals)
#         stats[f'{metric}_std'] = np.std(vals)
    
#     return stats
# ************************************************************* <-- Claude Generated

def _calculate_fft_stats(feature_list: list) -> dict:
    """
    Helper function to calculate mean/std and extract all values 
    for all four FFT features from a list of feature dictionaries.
    """
    if not feature_list:
        return {}
        
    stats = {}
    
    # Define the four features we want to analyze
    metrics = ['fft_energy', 'fft_entropy', 'dominant_freq', 'hf_lf_ratio']
    
    for metric in metrics:
        # Extract the list of values for the current metric
        vals = [d[metric] for d in feature_list]
        
        # Calculate statistics
        mean_val, std_val = np.mean(vals), np.std(vals)
        
        # Store results in the dictionary
        stats[f'{metric}_vals'] = vals
        stats[f'{metric}_mean'] = mean_val
        stats[f'{metric}_std'] = std_val
        
    return stats

# this ruleset uses all conn.log files across all nodes/pods to create a distribution as follows:
# def extract_fft_ruleset_conn(window_size=0):
#     conn_paths = [
#         # NEW BENIGN DATA PATHS (10 MINUTE)
#         "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",                                 # [0]
#         "../../train_test_data/new-benign_10_min/csv/child2/conn.csv",                                 # [1]
#         "../../train_test_data/new-benign_10_min/csv/cam-pod/conn.csv",                                # [2]
#         "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv",                              # [3]
#         "../../train_test_data/new-benign_10_min/csv/nginx-pod/conn.csv",                              # [4]
#     ]
#     NUMERIC_COLS = [
#         'orig_bytes', 'resp_bytes',
#         'orig_pkts', 'resp_pkts',
#         'duration'
#     ]
    
#     timestamp_benign_feats = []
#     bps_benign_feats = []
#     pps_benign_feats = []
#     conn_benign_feats = []
    
#     # **************************************************************** <-- BEGIN: Derive fetures based on entire datasets
#     for path in conn_paths:    
#         df = pd.read_csv(path)
        
#         # filter out incomplete transactions
#         # has_sentinel = (df[NUMERIC_COLS] == '-').any(axis=1)
#         # rows_to_keep = ~has_sentinel
#         # df = df[rows_to_keep]
        
#         for col in NUMERIC_COLS:
#             df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
#         timestamp_benign_feats.append(fft_timestamps_per_sec_conn(df))
#         bps_benign_feats.append(fft_bytes_per_sec_conn(df))
#         pps_benign_feats.append(fft_packets_per_sec_conn(df))
#         conn_benign_feats.append(fft_conncount_per_sec_conn(df))
#     # **************************************************************** <-- END: Derive fetures based on entire datasets
    
#     # **************************************************************** <-- BEGIN: Derive features based on sliding windows over datasets (GPT generated)
#     # NEW CORRECT APPROACH:
#     # Build FFT ruleset using SLIDING WINDOWS over benign files.
#     # WINDOW_SIZE = window_size   # recommended baseline for your distributions

#     # for path in conn_paths:
#     #     df = pd.read_csv(path)

#     #     for col in NUMERIC_COLS:
#     #         df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

#     #     total_rows = len(df)

#     #     # Slide window through the dataframe with stride
#     #     stride = WINDOW_SIZE // 2  # 50% overlap to get more samples
#     #     for start in range(0, total_rows - WINDOW_SIZE + 1, stride):
#     #         end = start + WINDOW_SIZE
#     #         win_df = df.iloc[start:end]

#     #         # compute FFT features for this window
#     #         timestamp_benign_feats.append(fft_timestamps_per_sec_conn(win_df))
#     #         bps_benign_feats.append(fft_bytes_per_sec_conn(win_df))
#     #         pps_benign_feats.append(fft_packets_per_sec_conn(win_df))
#     #         conn_benign_feats.append(fft_conncount_per_sec_conn(win_df))
#     # **************************************************************** <-- END: Derive features based on sliding windows over datasets (GPT generated)
    
    
#     # the return dict
#     result = {
#         'timestamp' : _calculate_fft_stats(timestamp_benign_feats),
#         'bps' : _calculate_fft_stats(bps_benign_feats),
#         'pps' : _calculate_fft_stats(pps_benign_feats),
#         'conn' : _calculate_fft_stats(conn_benign_feats)
#     }
    
#     return result

def extract_fft_ruleset_conn(window_size=500):
    conn_paths = [
        "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",
        "../../train_test_data/new-benign_10_min/csv/child2/conn.csv",
        "../../train_test_data/new-benign_10_min/csv/cam-pod/conn.csv",
        "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv",
        "../../train_test_data/new-benign_10_min/csv/nginx-pod/conn.csv",
    ]

    NUMERIC_COLS = ['orig_bytes','resp_bytes','orig_pkts','resp_pkts','duration']

    timestamp_feats = []
    bps_feats = []
    pps_feats = []
    conn_feats = []

    # ============================
    # 1. Entire-dataset FFT samples
    # ============================
    for path in conn_paths:
        df = pd.read_csv(path)

        for col in NUMERIC_COLS:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

        timestamp_feats.append(fft_timestamps_per_sec_conn(df))
        bps_feats.append(fft_bytes_per_sec_conn(df))
        pps_feats.append(fft_packets_per_sec_conn(df))
        conn_feats.append(fft_conncount_per_sec_conn(df))

    # ============================
    # 2. Sliding-window FFT samples
    # ============================
    # WINDOW = window_size
    # STRIDE = WINDOW // 2

    # for path in conn_paths:
    #     df = pd.read_csv(path)
    #     for col in NUMERIC_COLS:
    #         df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    #     rows = len(df)
    #     for start in range(0, rows - WINDOW + 1, STRIDE):
    #         win = df.iloc[start:start+WINDOW]

    #         timestamp_feats.append(fft_timestamps_per_sec_conn(win))
    #         bps_feats.append(fft_bytes_per_sec_conn(win))
    #         pps_feats.append(fft_packets_per_sec_conn(win))
    #         conn_feats.append(fft_conncount_per_sec_conn(win))

    # ============================
    # 3. Build ruleset
    # ============================
    result = {
        'timestamp': _calculate_fft_stats(timestamp_feats),
        'bps':       _calculate_fft_stats(bps_feats),
        'pps':       _calculate_fft_stats(pps_feats),
        'conn':      _calculate_fft_stats(conn_feats)
    }

    return result


# TESTING
# conn_paths = [
#         "../../train_test_data/benign_1_min/node-1-child-3/csv files/node1_conn.csv",           # [0]
#         "../../train_test_data/benign_1_min/node-2-child-4/csv files/node2_conn.csv",           # [1]
#         "../../train_test_data/benign_1_min/cam-pod/csv files/camera_conn.csv",                 # [2]
#         "../../train_test_data/benign_1_min/lidar-pod/csv files/lidar_conn.csv",                # [3]
#         "../../train_test_data/benign_1_min/nginx-pod/csv files/NGINX_conn.csv",                # [4]
#         "../../train_test_data/benign_sim/csv/conn.csv",                                        # [5] benign
#         "../../train_test_data/ddos_sim/csv/conn_malignant1.csv",                               # [6] malignant
        
#         # NEW BENIGN DATA PATHS
#         # "../../train_test_data/new-benign/csv/child1/conn.csv",                                 # [7]
#         # "../../train_test_data/new-benign/csv/child2/conn.csv",                                 # [8]
#         # "../../train_test_data/new-benign/csv/cam-pod/conn.csv",                                # [9]
#         # "../../train_test_data/new-benign/csv/lidar-pod/conn.csv",                              # [10]
#         # "../../train_test_data/new-benign/csv/nginx-pod/conn.csv",                              # [11]
        
#         # NEW BENIGN DATA PATHS (10 MINUTE)
#         "../../train_test_data/new-benign_10_min/csv/child1/conn.csv",                                 # [7]
#         "../../train_test_data/new-benign_10_min/csv/child2/conn.csv",                                 # [8]
#         "../../train_test_data/new-benign_10_min/csv/cam-pod/conn.csv",                                # [9]
#         "../../train_test_data/new-benign_10_min/csv/lidar-pod/conn.csv",                              # [10]
#         "../../train_test_data/new-benign_10_min/csv/nginx-pod/conn.csv",                              # [11]
        
        
#         # NEW MALIGNANT DATA PATHS
#         "../../train_test_data/lidar-attack/csv/child1/conn.csv",                               # [12]
#         "../../train_test_data/lidar-attack/csv/child2/conn.csv",                               # [13]
#         "../../train_test_data/lidar-attack/csv/cam-pod/conn.csv",                              # [14]
#         "../../train_test_data/lidar-attack/csv/lidar-pod/conn.csv",                            # [15]
#         "../../train_test_data/lidar-attack/csv/nginx-pod/conn.csv",                            # [16]
        
#         # COMBINED GENERALIZED BENIGN SET
#         # "../../train_test_data/combined_benign_conn.csv"                                        # [17]
# ]


# NUMERIC_COLS = [
#     'orig_bytes', 'resp_bytes',
#     'orig_pkts', 'resp_pkts',
#     'duration'
# ]

# benign_sets = [7, 8, 9, 10, 11]
# malignant_sets = [12, 13, 14, 15, 16]

# # benign_sets = [5]
# # malignant_sets = [6]

# timestamp_benign_feats, bps_benign_feats, pps_benign_feats, conn_benign_feats = [], [], [], []
# timestamp_malignant_feats, bps_malignant_feats, pps_malignant_feats, conn_malignant_feats = [], [], [], []

# # We define a processing order: (List of Indices, Label, Destination Lists)
# processing_groups = [
#     (benign_sets, "BENIGN", [timestamp_benign_feats, bps_benign_feats, pps_benign_feats, conn_benign_feats]),
#     (malignant_sets, "MALIGNANT", [timestamp_malignant_feats, bps_malignant_feats, pps_malignant_feats, conn_malignant_feats])
# ]

# # --- Main Loop ---

# for indices, label_name, target_lists in processing_groups:
    
#     # Unpack the specific target lists for this group
#     target_ts, target_bps, target_pps, target_conn = target_lists

#     for i in indices:
#         path = conn_paths[i]
        
#         # 1. Data Loading
#         df = pd.read_csv(path)
#         for col in NUMERIC_COLS:
#             df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

#         # 2. Raw FFT Calculation
#         # timestamp_fft_raw = raw_fft_timestamps_per_sec_conn(df)
#         # bps_fft_raw = raw_fft_bytes_per_sec_conn(df)
#         # pps_fft_raw = raw_fft_packets_per_sec_conn(df)
#         # conn_fft_raw = raw_fft_conncount_per_sec_conn(df)
        
#         # 3. Feature Extraction
#         timestamp_fft_feats = fft_timestamps_per_sec_conn(df)
#         bps_fft_feats = fft_bytes_per_sec_conn(df)
#         pps_fft_feats = fft_packets_per_sec_conn(df)
#         conn_fft_feats = fft_conncount_per_sec_conn(df)
        
#         # 4. Append to the CORRECT list (Guaranteed by the loop structure)
#         target_ts.append(timestamp_fft_feats)
#         target_bps.append(bps_fft_feats)
#         target_pps.append(pps_fft_feats)
#         target_conn.append(conn_fft_feats)

#         # 5. Logging
#         # print("*********************************************")
#         # print(f"{label_name} SET: [{path}] (Index: {i})")
        
#         # print("Timestamp FFT Features:"); print_dict(timestamp_fft_feats)
#         # print("Bytes/sec FFT Features:"); print_dict(bps_fft_feats)
#         # print("Packets/sec FFT Features:"); print_dict(pps_fft_feats)
#         # print("Conn/sec FFT Features:"); print_dict(conn_fft_feats)
#         # print("*********************************************")

#         # 6. Plotting
#         # fig, axes = plt.subplots(2, 2, figsize=(16, 10))
#         # fig.suptitle(f"{label_name} Dataset: [{path}]", fontsize=16)

#         # # Plot helper
#         # def plot_fft(ax, data, title):
#         #     ax.plot(data)
#         #     ax.set_title(title)
#         #     ax.set_xlabel("Frequency")
#         #     ax.set_ylabel("Magnitude")

#         # plot_fft(axes[0, 0], timestamp_fft_raw, "Timestamps-per-second FFT")
#         # plot_fft(axes[0, 1], bps_fft_raw, "Bytes-per-second FFT")
#         # plot_fft(axes[1, 0], pps_fft_raw, "Packets-per-second FFT")
#         # plot_fft(axes[1, 1], conn_fft_raw, "Connections-per-second FFT")

#         # plt.tight_layout(rect=[0, 0.03, 1, 0.95]) # Adjust for suptitle
        
#         # Save using the label_name variable
#         # plt.savefig(f"./ffts/{label_name.lower()}_fft_{i}.png")
#         # plt.show() 
#         # plt.close(fig) # Close to free memory
        

# # 1. Organize your lists into pairs for easy iteration
# # Format: (Category Name, Benign List, Malignant List)
# data_groups = [
#     ("Timestamp", timestamp_benign_feats, timestamp_malignant_feats),
#     ("Bytes Per Sec (BPS)", bps_benign_feats, bps_malignant_feats),
#     ("Packets Per Sec (PPS)", pps_benign_feats, pps_malignant_feats),
#     ("Connections", conn_benign_feats, conn_malignant_feats)
# ]

# # The specific keys inside your dictionaries
# metrics = ["fft_energy", "fft_entropy", "dominant_freq", "hf_lf_ratio"]# ["fft_energy", "fft_entropy", "dominant_freq", "hf_lf_ratio"]

# # 2. Loop through each category
# for category, benign_list, mal_list in data_groups:
#     print(f"\n{'='*20} {category} Analysis {'='*20}")
    
#     # Print Table Header
#     print(f"{'Feature':<20} | {'Benign (Mean ± Std)':<30} | {'Malignant (Mean ± Std)':<30}")
#     print("-" * 85)

#     # 3. Loop through each metric (energy, entropy, etc.)
#     for metric in metrics:
#         # Extract the list of values for this specific metric
#         # Check if list is empty to avoid crashing
#         if benign_list:
#             b_vals = [d[metric] for d in benign_list]
#             b_mean, b_std = np.mean(b_vals), np.std(b_vals)
#         else:
#             b_mean, b_std = 0.0, 0.0

#         if mal_list:
#             m_vals = [d[metric] for d in mal_list]
#             m_mean, m_std = np.mean(m_vals), np.std(m_vals)
#         else:
#             m_mean, m_std = 0.0, 0.0

#         # Print the row formatted to 4 decimal places
#         if metric == "fft_energy":
#             # format the large energies
#             print(f"{metric:<20} | {b_mean:>10.4e} ± {b_std:<10.4e} (CV = {(b_std/b_mean):.2f})    | {m_mean:>10.4e} ± {m_std:<10.4e} (CV = {(m_std/m_mean):.2f})    | Ratio (Mean): {(b_mean / m_mean):.2f}")
#         else:
#             print(f"{metric:<20} | {b_mean:>10.4f} ± {b_std:<10.4f} (CV = {(b_std/b_mean):.2f})    | {m_mean:>10.4f} ± {m_std:<10.4f} (CV = {(m_std/m_mean):.2f})")
            
# print()
# print()
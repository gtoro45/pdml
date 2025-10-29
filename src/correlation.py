import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Load your Zeek dataset
path = "/mnt/c/Users/gabri/Desktop/benign - 1 minute - processed/training_data/node1_conn.csv"
df = pd.read_csv(path)
# Select only numeric columns
df_numeric = df.select_dtypes(include=[np.number]).dropna()

# Compute mean vector, covariance matrix, and correlation matrix
mu = df_numeric.mean()
cov_matrix = df_numeric.cov()
corr_matrix = df_numeric.corr()

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
sns.heatmap(corr_matrix, ax=axes[2], cmap="coolwarm", cbar=True, center=0)
axes[2].set_title("Correlation Matrix (R)")
axes[2].xaxis.set_ticks_position('bottom')
axes[2].xaxis.set_label_position('bottom')

plt.tight_layout()
plt.show()

from encoding import *
from rules import *
import argparse
import sys

# ******************************************************
# THIS CODE IS RAN PER NODE/CHILD IN THE KUBERNETES 
# CLUSTER, AND THEREFORE TAKES THAT IN AS INPUT FOR THE
# MODELS AND RULES TO LOAD PROPERLY FROM CORRECT PATHS
# ******************************************************
parser = argparse.ArgumentParser(description='Process logs with specified node/child (module)')
parser.add_argument(
    '--module',
    type=str,
    required=True,
    help='node/child to process data from'
)
args = parser.parse_args()
# TODO -- PREFIXES

# ==== Paths to Models and Rules, and CSV Buffer for each log type ====
CONN_DATA_PATHS = [
    
]

DNS_DATA_PATHS = [
    
]

SSL_DATA_PATHS = [
    
]

HTTP_DATA_PATHS = [
    
]

WEIRD_DATA_PATHS = [
    
]

# ==== Instantiate the Models, Rules, and Buffers ====
# models

# rules

# buffers (for rate checking)
conn_count = 0
dns_count = 0
ssl_count = 0
http_count = 0
last_100_conn = []
last_100_dns = []
last_100_ssl = []
last_100_http = []

# ==== Main Function ====
def main():
    
    return 0   
    
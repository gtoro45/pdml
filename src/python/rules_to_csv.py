import csv
import re

# Read the input file
with open('rules.out', 'r') as f:
    content = f.read()

# Split by dataset sections
datasets = content.split('Dataset: [')
datasets = [d for d in datasets if d.strip()]

# Prepare data structure
data_rows = []
headers = ['metric']

# Parse each dataset
for dataset in datasets:
    lines = dataset.split('\n')
    dataset_name = lines[0].split(']')[0]
    
    # Extract all metrics
    metrics = {}
    for line in lines:
        if ':' in line and not line.startswith('=') and not line.startswith('*'):
            # Clean up the line
            line = line.strip()
            if line.startswith('Dataset:'):
                continue
            
            # Split on first colon
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                
                # Try to extract numeric value (ignore text in parentheses)
                # Remove anything in parentheses
                value_clean = re.sub(r'\(.*?\)', '', value).strip()
                
                # Handle "No data available" or "nan"
                if 'No data available' in value or value_clean == 'nan':
                    value_clean = '-1'
                
                metrics[key] = value_clean
    
    # Add to headers if not already there
    if dataset_name not in headers:
        headers.append(dataset_name)
    
    # Store metrics for this dataset
    data_rows.append((dataset_name, metrics))

# Get all unique metric names across all datasets
all_metrics = set()
for _, metrics in data_rows:
    all_metrics.update(metrics.keys())

all_metrics = sorted(list(all_metrics))

# Create CSV output
output_data = []

# First row is headers
output_data.append(headers)

# Each subsequent row is a metric
for metric in all_metrics:
    row = [metric]
    for dataset_name in headers[1:]:
        # Find the metrics for this dataset
        value = '-1'
        for ds_name, metrics in data_rows:
            if ds_name == dataset_name:
                value = metrics.get(metric, '-1')
                break
        row.append(value)
    output_data.append(row)

# Write to CSV
with open('network_statistics.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerows(output_data)

print(f"CSV file created with {len(headers)-1} datasets and {len(all_metrics)} metrics")
print(f"Output file: network_statistics.csv")
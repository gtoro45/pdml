#!/usr/bin/env python3
import csv, sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} input.log output.csv")
    sys.exit(1)

input_file, output_file = sys.argv[1], sys.argv[2]

# Read header line
with open(input_file, encoding='utf-8') as f:
    for line in f:
        if line.startswith("#fields"):
            fields = line.strip().split('\t')[1:]
            break

# Convert body
with open(input_file, encoding='utf-8') as fin, open(output_file, 'w', newline='', encoding='utf-8') as fout:
    writer = csv.writer(fout)
    writer.writerow(fields)
    for line in fin:
        if not line.startswith('#') and line.strip():
            writer.writerow(line.strip().split('\t'))

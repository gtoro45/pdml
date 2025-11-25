# pdml
PCAP Detection Model 

This is the network ML subsystem for the Cyber Threat capstone project at Texas A&M Univerity. 

## Components
- `format.c`: extracts and format Zeek logs into CSV format for training and testing
    - input: Zeek log file path (real-time file)
    - output: CSV file buffer with csv-ready log lines for python modelling
- FIFO (UNIX pipe) to store ready to go input data to feed into model
- `*.py`: detection model (ffts, rulesets, etc.) and script to run in real-time

## Dependencies
The following dependencies are required to run this project:

- Linux/UNIX syscalls and architecture
- Zeek 8.0.1 --> PCAP extraction stage
    - Built from source: https://github.com/zeek/zeek
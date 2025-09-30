# pdml
PCAP Detection Model 

This is the network ML subsystem for the Cyber Threat capstone project at Texas A&M Univerity. 

## Components
- `format.c`: extracts and format Zeek logs into CSV format for training and testing
    - input: PCAP file path
    - output: CSV file with model inputs placed into a waiting queue for the detection model
- FIFO (UNIX pipe) to store ready to go input data to feed into model
- `model.py`: detection model training + running script

## Dependencies
The following dependencies are required to run this project:

- Linux/UNIX syscalls and architecture
- Zeek 8.0.1 --> PCAP extraction stage
    - Built from source: https://github.com/zeek/zeek
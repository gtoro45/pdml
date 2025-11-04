#!/bin/bash

# Parse command-line arguments
DEBUG=0
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--debug)
            DEBUG=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-d|--debug]"
            exit 1
            ;;
    esac
done

# Constants and paths
mkdir -p ../tests/
ZEEK_LOG_DIR=../tests
FORMAT_BINARY_PATH=../c
INTERFACE="enp7s0"

# Clean up any existing log files (replace with final log paths)
rm -rf $ZEEK_LOG_DIR/*.log

# Zeek to be launched for all interfaces being read
pushd $ZEEK_LOG_DIR
sudo nohup /usr/local/zeek/bin/zeek -i $INTERFACE > $LOG_PATH/zeek_output.log 2>&1 < /dev/null &
popd

# Run the program
reset

pushd $FORMAT_BINARY_PATH
if [ $DEBUG -eq 1 ]; then
    # Debug mode (Valgrind)
    make clean
    make debug
    mv *.o pdml ../../bin/
    pushd ../../bin/
    taskset -c 0-3 valgrind -s --leak-check=full --show-leak-kinds=all --track-origins=yes ./pdml
    popd
else
    make clean
    make
    mv *.o pdml ../../bin/
    pushd ../../bin/
    ./pdml
    popd
fi
popd

sudo pkill zeek
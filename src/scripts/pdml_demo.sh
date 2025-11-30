#!/bin/bash

# (0) Place all backgrounded processes in same group for easier shutdown
# set -m                # enable job control

# cleanup() {
#     echo "Cleaning up..."
#     # kill whole process group
#     kill 0
# }
# trap cleanup EXIT

# (1) Launch the Python reader and writer script to feed raw conn.log data into the formatter as a "live" file
READ_LOG="../../train_test_data/demo/demo_conn.log"              # <-- stream line by line from this file
WRITE_LOG="../../train_test_data/demo/conn.log"                  # <-- to this file
python3 ../python/live_sim.py $READ_LOG $WRITE_LOG -d 10 &       # 100ms between lines

# (2) Launch the formatter with valgrind --> WRITING to demo_buf.csv
FORMAT_BINARY_PATH=../c
pushd $FORMAT_BINARY_PATH
make clean
make debug
mv *.o pdml ../../bin/
pushd ../../bin/
taskset -c 0-3 valgrind -s \
                --leak-check=full \
                --show-leak-kinds=all \
                --track-origins=yes \
                ./pdml > ../src/scripts/format.log 2>&1 &  
popd
popd

# (3) Launch pdml.py --> READING from demo_buf.csv
python3 ../python/pdml.py

# (4) Dummy wait so script doesn't exit
wait

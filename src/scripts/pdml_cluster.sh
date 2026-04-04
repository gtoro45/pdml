#(0) Get the absolute path to the project root
PROJECT_ROOT=$(realpath "../../")

# (1) run zeek and get log file path
ZEEK_CONN_LOG_PATH="$PROJECT_ROOT/gcri/logs"
mkdir -p $ZEEK_CONN_LOG_PATH
rm -rf $ZEEK_CONN_LOG_PATH/*.log
pushd $ZEEK_CONN_LOG_PATH > /dev/null 

# Use nohup to detach and ensure it doesn't die when the script ends
# 'local' ensures standard logging policies are loaded
sudo nohup /opt/zeek/bin/zeek -i any > /dev/null 2>&1 &        # GCRI Cluster
# sudo nohup /usr/local/zeek/bin/zeek -i any > /dev/null 2>&1 &    # Laptop

# Store the PID so you can kill it later
ZEEK_PID=$!
popd > /dev/null 
echo "Zeek started on PID $ZEEK_PID. Waiting for conn.log..."

# wait for conn.log to actually exist
until [ -f "$ZEEK_CONN_LOG_PATH/conn.log" ]; do
  sleep 1
done
echo "Found conn.log, proceeding..."
sleep 5
reset

# (2) prepare the csv buffer
mkdir -p ../../buf
rm -f ../../buf/buffer.csv
touch ../../buf/buffer.csv
sudo chmod 777 ../../buf/buffer.csv

# (3) Launch the formatter with valgrind --> WRITING to demo_buf.csv
FORMAT_BINARY_PATH="$PROJECT_ROOT/src/c"
pushd $FORMAT_BINARY_PATH > /dev/null
make clean
make debug
mv -f *.o pdml "$PROJECT_ROOT/bin/"
pushd "$PROJECT_ROOT/bin/"
taskset -c 0-3 valgrind -s \
                --leak-check=full \
                --show-leak-kinds=all \
                --track-origins=yes \
                ./pdml $ZEEK_CONN_LOG_PATH > ../src/scripts/format.log 2>&1 &  
popd

# (4) Launch pdml.py --> READING from demo_buf.csv
python3 "$PROJECT_ROOT/src/python/pdml.py"
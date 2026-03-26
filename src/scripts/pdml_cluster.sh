# (1) run zeek and get log file path
ZEEK_CONN_LOG_PATH="../../gcri/logs"
mkdir -p $ZEEK_CONN_LOG_PATH
pushd $ZEEK_CONN_LOG_PATH

# Use nohup to detach and ensure it doesn't die when the script ends
# 'local' ensures standard logging policies are loaded
sudo nohup /opt/zeek/bin/zeek -i lo local > /dev/null 2>&1 &

# Store the PID so you can kill it later
ZEEK_PID=$!
popd

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
FORMAT_BINARY_PATH=../c
pushd $FORMAT_BINARY_PATH
make clean
make debug
mv -f *.o pdml ../../bin/
pushd ../../bin/
taskset -c 0-3 valgrind -s \
                --leak-check=full \
                --show-leak-kinds=all \
                --track-origins=yes \
                ./pdml $ZEEK_CONN_LOG_PATH > ../src/scripts/format.log 2>&1 &  
popd

# (4) Launch pdml.py --> READING from demo_buf.csv
python3 ../python/pdml.py
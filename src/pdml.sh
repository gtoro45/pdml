# Clean up any existing log files
rm -rf /mnt/c/Users/gabri/Desktop/School/capstone/pdml/src/tests/*.log # replace with log paths

# Zeek to be launched for all interfaces being read
LOG_PATH=/mnt/c/Users/gabri/Desktop/School/capstone/pdml/src/tests # replace with log path
cd $LOG_PATH
sudo nohup /usr/local/zeek/bin/zeek -i eth0 > $LOG_PATH/zeek_output.log 2>&1 < /dev/null &

sudo /usr/local/zeek/bin/zeek -i eth0 > /dev/null 2>&1 &


# Run the program
reset
cd /mnt/c/Users/gabri/Desktop/School/capstone/pdml/src # replace with binary path
make clean
make
./pdml
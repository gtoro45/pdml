# Clean up any existing log files (replace with final log paths)
rm -rf /mnt/c/Users/gabri/Desktop/School/capstone/pdml/src/tests/*.log  # Gabe LAPTOP
# rm -rf /home/gabrieltoro45/capstone/pdml/src/tests/*.log               # Gabe DESKTOP

# Zeek to be launched for all interfaces being read
LOG_PATH=/mnt/c/Users/gabri/Desktop/School/capstone/pdml/src/tests # Gabe LAPTOP
# LOG_PATH=/home/gabrieltoro45/capstone/pdml/src/tests                         # Gabe DESKTOP
cd $LOG_PATH
sudo nohup /usr/local/zeek/bin/zeek -i eth0 > $LOG_PATH/zeek_output.log 2>&1 < /dev/null &
# sudo /usr/local/zeek/bin/zeek -i eth0 > /dev/null 2>&1 &


# Run the program
reset
cd /mnt/c/Users/gabri/Desktop/School/capstone/pdml/src  # Gabe LAPTOP
# cd /home/gabrieltoro45/capstone/pdml/src               # Gabe Desktop
make clean
make debug
mv *.o pdml ../bin/
cd /mnt/c/Users/gabri/Desktop/School/capstone/pdml/bin  # Gabe LAPTOP
# cd /home/gabrieltoro45/capstone/pdml/bin               # Gabe Desktop

# Run with Valgrind
taskset -c 0-3 valgrind -s --leak-check=full --show-leak-kinds=all --track-origins=yes ./pdml

# Run with -fsanitize debug tools
# taskset -c 0-3 ./pdml


# Kill off Zeek
sudo pkill zeek
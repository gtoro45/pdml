# To be launched for all interfaces being read
cd /mnt/c/Users/gabri/Desktop/School/capstone/pdml/src/tests # replace with log paths
echo "Zeek process listening to [eth0] launched"
sudo /usr/local/zeek/bin/zeek -i eth0 > /dev/null 2>&1 &


# Run the program
cd /mnt/c/Users/gabri/Desktop/School/capstone/pdml/src # replace with binary path
make clean
make
./pdml

# Clean on exit
wait
rm -rf /mnt/c/Users/gabri/Desktop/School/capstone/pdml/src/tests/*.log # replace with log paths
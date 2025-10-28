# Clean up any existing log files 
# daemon-logs
rm -rf /home/capstone/Desktop/cluster/daemon-logs/conn.log
rm -rf /home/capstone/Desktop/cluster/daemon-logs/dns.log
rm -rf /home/capstone/Desktop/cluster/daemon-logs/http.log
rm -rf /home/capstone/Desktop/cluster/daemon-logs/ssl.log
rm -rf /home/capstone/Desktop/cluster/daemon-logs/weird.log


# Launch Zeek on all the pods (modified from team2.bash)
echo "Launching zeek on all nodes/pods"
pushd /home/capstone/Desktop/livetracks
bash daemon-enable.bash
bash camera-live-enable.bash
bash lidar-live-enable.bash
bash nginx-live-enable.bash
popd


# Run the program
echo "Launching pdml subsystem"
pushd /home/capstone/Desktop/team2/gabe/pdml/src
make clean
make
taskset -c 1-2 ./pdml /home/capstone/Desktop/cluster/daemon-logs daemon-logs
taskset -c 3-4 ./pdml /home/capstone/Desktop/cluster/zeek-logs-camera zeek-logs-camera
taskset -c 5-6 ./pdml /home/capstone/Desktop/cluster/zeek-logs-lidar zeek-logs-lidar
taskset -c 7-8 ./pdml /home/capstone/Desktop/cluster/zeek-logs-nginx zeek-logs-nginx
popd

# Kill the Zeek instances
echo "Killing zeek on all nodes/pods"
pushd /home/capstone/Desktop/livetracks
bash daemon-live-disable.bash
bash camera-live-disable.bash
bash lidar-live-disable.bash
bash nginx-live-disable.bash
popd
sudo pkill zeek
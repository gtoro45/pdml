/* 
    Description: C++ program to extract and format Zeek logs into CSV format for training and testing
    Author: Gabriel Toro
    Date: 9/23/25

*/
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <unistd.h>

void extract(std::string pcap_path) {
    // Use execvp to call zeek extraction process
    std::string command = "/usr/local/zeek/bin/zeek";
    // TODO
}

void format() {

}

int main() {
    extract();
    return 0;
}

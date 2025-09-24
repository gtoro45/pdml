/* 
    Description: C++ program to extract and format Zeek logs into CSV format for training and testing
    Author: Gabriel Toro
    Date: 9/23/25

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


void extract(char* pcap_path) {
    // Use execvp to call zeek extraction process (fork() + execvp())
    pid_t pid = fork();
    // Fork failure
    if(pid < 0) {
        perror("zeek extraction process fork failed");
        exit(1);
    }
    // Child process
    else if(pid == 0) {
        //TODO: call zeek script with execvp()
    }
    // Parent process
    else {
        //TODO: wait for child process to finish
    }
    

    // TODO
    
}

void format() {

}

int main() {
    char* pcap_path;
    extract(pcap_path);
    return 0;
}

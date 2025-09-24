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
        //call zeek script with execvp()
        char* cmd = "/usr/local/zeek/bin/zeek";
        char* argv[3];
        agrv[0] = cmd;
        argv[1] = "-r";
        argv[2] = pcap_path;
        argv[3] = "extract.zeek";
        argv[4] = NULL; 
        if(execvp(cmd, argv) < 0) {     //execvp being called here inside if statement to check for failure
            perror("zeek extraction process exec failed");
            exit(1); 
        }
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

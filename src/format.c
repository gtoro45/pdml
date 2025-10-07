#include "zeek_csv.h"
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>

/** 
 * Function to launch zeek for live logging, to be read in the main function
 * This needs to be launced for ALL interfaces being read
 */
void launch_zeek(char* interface, char* script_path) {
    pid_t pid = fork();
    if(pid < 0) {
        perror("Zeek launch process fork failed");
        exit(1);
    }
    // CHILD PROCESS
    if(pid == 0) {
        // call zeek script for live reading with execvp()
        char* cmd = "sudo";
        char* argv[6];
        argv[0] = cmd;
        argv[1] = "/usr/local/zeek/bin/zeek";
        argv[2] = "-i";
        argv[3] = interface;
        argv[4] = script_path;
        argv[5] = NULL;

        if(execvp(cmd, argv) < 0) {     //execvp being called here inside if statement to check for failure
                perror("Zeek extraction process exec failed");
                exit(1); 
        }
    }
    // PARENT PROCESS
    else {
        printf("Zeek process listening to [%s] launched with PID: %d", interface, pid);
    }
}

int main() {
    // to be launched for all interfaces being read
    launch_zeek("eth0", NULL);
    return 0;
}
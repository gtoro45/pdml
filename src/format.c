/* 
    Description: C program to extract and format Zeek logs into CSV format for training and testing
    Author: Gabriel Toro
    Date: 9/23/25

*/
#define _GNU_SOURCE
#include "zeek_csv.h"
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>



/************************ General Helper Functions ************************/

/************************ Zeek Extraction and Processing ************************/
// Define the input CSV queue (filepaths to csvs are FIFO's here after formatting)
char** input_queue;

void format(char* pcap_path) {
    // identify all the important log files in the path

    // TODO: FORMAT THEN FIFO
}

void* extract(void* arg) {
    // Cast arg back to cstring
    char* pcap_path = (char*)arg;

    // Check Scheduler CPU affinity
    printf("Thread running on CPU %d\n", sched_getcpu());

    // create a unique logfile ID so that both parent and child have access to the same ID
    // djb2 hashing algorithm
    char* tmp = pcap_path;      // used so that actual PCAP file path is not changed by advancing the pointer
    unsigned long hash = 5381;
    int c;
    while(c = *tmp++) { hash = ((hash << 5) + hash) + c; }
    unsigned long thread_id = hash;
    

    // Use execvp to call zeek extraction process (fork() + execvp())
    pid_t pid = fork();
    // Fork failure
    if(pid < 0) {
        perror("zeek extraction process fork failed");
        exit(1);
    }
    // Child process
    else if(pid == 0) {
        //create the log file folder using the global thread ID
        char logdir[128];
        snprintf(logdir, sizeof(logdir), "./logs/%ld", thread_id);
        if(mkdir(logdir, 0777) < 0 && errno != EEXIST) {
            perror("mkdir failed");
            exit(1);
        }
        char logdir_arg[256];
        snprintf(logdir_arg, sizeof(logdir_arg), "Log::default_logdir=%s", logdir);
        
        //call zeek script with execvp()
        char* cmd = "/usr/local/zeek/bin/zeek";
        char* argv[6];
        argv[0] = cmd;
        argv[1] = "-r";
        argv[2] = pcap_path;
        argv[3] = "extract.zeek";
        argv[4] = logdir_arg;
        argv[5] = NULL; 
        if(execvp(cmd, argv) < 0) {     //execvp being called here inside if statement to check for failure
            perror("Zeek extraction process exec failed");
            exit(1); 
        }
    }
    // Parent process
    else {
        //wait for child process to finish
        wait(NULL);
        printf("\nZeek extraction completed: logs stored in logs/%ld\n", thread_id);

        //call formatting function
        format(pcap_path);

        // TODO: decrement the active thread counter
    }
}


/************************ Main Program ************************/
int main() {
    char* log_path = "../src/logs/1756495414760718325/conn.log";
    char** lines = extract_lines(log_path); // needs to be freed
    int i = 0;
    while(lines[i] != NULL) {
        char* formatted = csvify_line(lines[i]);
        printf("%s", formatted);
        free(formatted);
        free(lines[i]);
        i++;
    }
    printf("\n");



    // char* pcap_path1 = "../benign_1_min/Node 1 (Child 3)/node-child3-1757872962.pcap";
    // char* pcap_path2 = "../benign_1_min/Node 2 (Child 4)/fixed_node-child4-1757872963.pcap";
    // char* pcap_path3 = "../benign_1_min/Camera Pod/camera-usb-camera-two-1757872962.pcap";
    // char* pcap_path4 = "../benign_1_min/NGINX Pod/webserver-nginx-5c5d44f994-hswwh-1757872964.pcap";
    // char* pcap_path5 = "../benign_1_min/LiDAR Pod/lidar-usb-lidar-1757872963.pcap";
    

    // // detect environment
    // long nprocs = sysconf(_SC_NPROCESSORS_ONLN);

    // // create threads
    // pthread_t thread1;
    // pthread_t thread2;
    // pthread_t thread3;
    // pthread_t thread4;
    // pthread_t thread5;

    // // spawn threads
    // pthread_create(&thread1, NULL, extract, pcap_path1);
    // pthread_create(&thread2, NULL, extract, pcap_path2);
    // pthread_create(&thread3, NULL, extract, pcap_path3);
    // pthread_create(&thread4, NULL, extract, pcap_path4);
    // pthread_create(&thread5, NULL, extract, pcap_path5);

    // // join threads
    // pthread_join(thread1, NULL);
    // pthread_join(thread2, NULL);
    // pthread_join(thread3, NULL);
    // pthread_join(thread4, NULL);
    // pthread_join(thread5, NULL);

    

    printf("\nThreads complete \n");
    

    return 0;
}

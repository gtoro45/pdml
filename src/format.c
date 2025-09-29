/* 
    Description: C program to extract and format Zeek logs into CSV format for training and testing
    Author: Gabriel Toro
    Date: 9/23/25

*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>


// Define the input CSV queue (filepaths to csvs are FIFO's here after formatting)
char** input_queue;


void* format(char* pcap_path) {
    // temp function
    int i = 0;
    while(pcap_path[i] != '\0') {
        printf("%c", pcap_path[i]);
        i++;
    }
    printf("\n");

}

void* extract(char* pcap_path) {
    // Check Scheduler CPU affinity
    printf("Thread running on CPU %d\n", sched_getcpu());

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
        argv[0] = cmd;
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
        //wait for child process to finish
        wait(NULL);
        printf("zeek extraction completed\n");

        //call formatting function
        format(pcap_path);
    }
}

/**
 * creates and pins a thread to an available CPU core
 * @param *thread: pointer to the thread to be created
 * @param *subroutine: the subroutine to be called
 * @param *arg: the data type or struct containing the subroutine arguments
 * @param *cpuset: the system's cpuset
 */
int create_and_pin_thread(pthread_t* thread, void* (*subroutine)(void *), void *arg, int nproc, int* cpus, int cpu_count) {
    // make sure CPU does not fall outside of nproc
    for(int cpu = 0; cpu < cpu_count; cpu++) {
        if(cpus[cpu] < 0 || cpus[cpu] > nproc - 1) {
        perror("Desired CPU affinity exceeds available cores on system");
        exit(1);
    }
    }
    
    // thread dependencies
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    for (int i = 0; i < cpu_count; i++) { CPU_SET(i, &cpuset); }
    
    // create the thread
    if(pthread_create(thread, NULL, subroutine, arg) != 0) {
        perror("Thread creation failure");
        exit(1);
    }

    // set thread affinity
    if(pthread_setaffinity_np(*thread, sizeof(cpu_set_t), &cpuset) != 0) {
        perror("Thread affinity failure");
        exit(1);
    }
    
    return 0;
}

int main() {
    char* pcap_path = "../benign_1_min/Node 1 (Child 3)/node-child3-1757872962.pcap";

    // create threads
    pthread_t thread1;
    pthread_t thread2;

    // create threads
    int nproc = 12; //will be found manually and account for SMT
    int cpus1[] = {0, 1};
    create_and_pin_thread(&thread1, extract, pcap_path, nproc, cpus1, 2);
    int cpus2[] = {5, 6};
    create_and_pin_thread(&thread2, extract, pcap_path, nproc, cpus2, 2);

    // join threads
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Threads complete \n");
    

    return 0;
}

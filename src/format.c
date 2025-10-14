#include "zeek_csv.h"
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>

/**
 * Function that formats the log file as it is updated live
 */
void* format(void* log_path) {
    // open the file once
    char* path = (char*) log_path;
    int fd;
    int timeout = 0;
    while((fd = open(path, O_RDONLY)) < 0) {
        printf("Zeek log file being established... (%d)\n", timeout);
        fflush(stdout);
        sleep(1);
        timeout++;
        if(timeout == 30) {
            perror("File could not be opened");
            exit(1);
        }
    }

    // continuously monitor the file for new lines to be added
    while(1) {
        char** lines = extract_lines(fd);
        for(int i = 0; lines[i] != NULL; i++) {
            char** line_tokens = tokenize_line(lines[i], HTTP);
            
            printf("[%s]: ", path);
            for(int j = 0; line_tokens[j] != NULL; j++) {
                printf("%s,", line_tokens[j]);
            }
            printf("\n");
            
            free_tokens(line_tokens);
        }
        free_lines(lines);
    }
    
    // close the file upon loop exit
    close(fd);
}

int main() {

    pthread_t thread1;
    pthread_t thread2;

    if(pthread_create(&thread1, NULL, format, "./tests/dns.log") < 0) {
        perror("pthread_create");
    }
    if(pthread_create(&thread2, NULL, format, "./tests/conn.log") < 0) {
        perror("pthread_create");
    }
    
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    
    
    return 0;
}
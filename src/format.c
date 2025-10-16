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
        printf("[%s] Zeek log file being established... (%d)\n", path, timeout);
        fflush(stdout);
        sleep(5);
        timeout += 5;
        if(timeout == 60) {
            perror("File could not be opened");
            exit(1);
        }
    }

    // continuously monitor the file for new lines to be added
    LineBuffer buf = {0};                               // previous buffer
    buf.incomplete_flag = false;
    while(1) {
        LineBuffer new_buf = extract_lines(fd);         // new buffer
        // check for previously incomplete flags (garbage collection hell)
        if(buf.incomplete_flag && new_buf.lines[0]) {
            /* -- Concatenation Logic --*/
            int len1 = strlen(buf.incomplete_line);                                 // record length of the incomplete line
            int len2 = strlen(new_buf.lines[0]);                                    // record length of the 2nd part of the incomplete line
            buf.incomplete_line = realloc(buf.incomplete_line, len1 + len2 + 1);    // realloc incomplete line memory to create space for 2nd part
            strcat(buf.incomplete_line, new_buf.lines[0]);                          // concatenate 2nd part of line to end of incomplete line --> complete line atp
            free(new_buf.lines[0]);                                                 // free the 0th element of lines, which contains the 2nd part of the line that we just concatenated
            new_buf.lines[0] = malloc((len1 + len2 + 1) * sizeof(char));            // malloc 0th element now to have enough space for the final, complete line
            strcpy(new_buf.lines[0], buf.incomplete_line);                          // copy over the complete line into that memory we just malloc'd
            free(buf.incomplete_line);                                              // free the old buffer's incomplete line, we are done with it
            buf.incomplete_line = NULL;
            buf.incomplete_flag = false;                                            // reset the previous buffer incomplete flag
        }

        // update the buffer state between loop iterations
        free_lines(buf.lines);
        buf.lines = NULL;
        buf.incomplete_line = new_buf.incomplete_line;
        buf.incomplete_flag = new_buf.incomplete_flag;
        
        // parse individual lines
        for(int i = 0; new_buf.lines[i] != NULL; i++) {
            char** line_tokens = tokenize_line(new_buf.lines[i], CONN);
            
            printf("[%s]: ", path);
            for(int j = 0; line_tokens[j] != NULL; j++) {
                printf("%s,", line_tokens[j]);
            }
            printf("\n");
            
            free_tokens(line_tokens);
        }
        free_lines(new_buf.lines);
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
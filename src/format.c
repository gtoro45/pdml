#include "zeek_csv.h"
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>

/** 
 * Function that identifies the .log file being read and returns the correct
 * enum type
 */
LogType get_type(char* path_to_file) {
    // traverse backwards up to "/" to index start of filename
    int len = strlen(path_to_file);
    int start_ind = -1;
    for(int i = len - 1; i >= 0; i--) {
        // beginning of string found at first slash OR if no slahses exist (i == 0)
        if(path_to_file[i] == '/') {
            start_ind = i + 1;
            break;
        }
        else if(i == 0) {
            start_ind = i;
            break;
        }
    }

    // parse the filename
    char name_buf[16] = {0};    // 16 bytes = next largest power of 2 that fits all log names
    int offset = 0;
    for(int i = start_ind; i < len; i++) {
        name_buf[offset] = path_to_file[i];
        offset++;
    }

    LogType result;
    if (strcmp(name_buf, "conn.log") == 0) result = CONN;
    else if (strcmp(name_buf, "dns.log") == 0) result = DNS;
    else if (strcmp(name_buf, "http.log") == 0) result = HTTP;
    else if (strcmp(name_buf, "ssl.log") == 0) result = SSL;
    else if (strcmp(name_buf, "weird.log") == 0) result = WEIRD;
    else result = UNKNOWN;
    
    return result;
}

/**
 * Function that formats the log file as it is updated live
 */
void* format(void* log_path) {
    // open the file once
    char* path = (char*) log_path;
    int fd;
    int timeout = 0;
    while((fd = open(path, O_RDONLY | O_NONBLOCK)) < 0) {
        if(timeout % 5 == 0) {
            printf("[%s] Zeek log file being established... (%d)\n", path, timeout);
            fflush(stdout);
        }
        sleep(1);
        timeout += 1;
        if(timeout == 60) {
            perror("File could not be opened");
            exit(1);
        }
    }
    printf("[%s]: Connection Established! (%d) \n", path, timeout);
    fflush(stdout);

    // mark the kind of log file the function is extracting
    LogType log_type = get_type(path);
    const char* log_type_str = logtype_to_str(log_type);

    // continuously monitor the file for new lines to be added
    LineBuffer buf = {0};                               // previous buffer
    int header_counter = 0;                             // counter for # of header lines before actual data
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
        if(buf.lines) {
            free_lines(buf.lines);
            buf.lines = NULL;
        }
        buf.incomplete_line = new_buf.incomplete_line;
        buf.incomplete_flag = new_buf.incomplete_flag;
        new_buf.incomplete_line = NULL;
        new_buf.incomplete_flag = false;
        
        // parse individual lines
        for(int i = 0; new_buf.lines[i] != NULL; i++) {
            if(header_counter >= 8) {
                // tokenize line
                char** line_tokens = tokenize_line(new_buf.lines[i], log_type);

                // convert tokens to csv-readable string
                char* line_csv = csvify_tokens(line_tokens);

                // catch incomplete line and alert user
                // free all allocated memory atp
                int count = 0;
                while (line_tokens[count] != NULL) count++;
                if(count != log_type) {
                    printf("[%s]: ERROR, unfinished line: %s", log_type_str, line_csv);
                    // TODO - fill with blanks to send partial data to FIFO
                    free_tokens(line_tokens);
                    free(line_csv);
                    continue;
                }

                // debug printing
                printf("[%s]: %s", log_type_str, line_csv);
                fflush(stdout);
                
                // write line to the UNIX FIFO 
                // TODO
                
                free_tokens(line_tokens);
                free(line_csv);
            }
            else {
                header_counter++;
            }
        }
        free_lines(new_buf.lines);
    }
    
    // close the file upon loop exit
    close(fd);
}

int main() {
    // pthread_t thread1;
    // pthread_t thread2;

    // if(pthread_create(&thread1, NULL, format, "./tests/dns.log") < 0) {
    //     perror("pthread_create");
    // }
    // if(pthread_create(&thread2, NULL, format, "./tests/conn.log") < 0) {
    //     perror("pthread_create");
    // }
    
    // pthread_join(thread1, NULL);
    // pthread_join(thread2, NULL);
    
    format("./tests/dns.log");

    // const char* test_paths[] = {
    //     "/var/log/zeek/conn.log",
    //     "/home/user/dns.log",
    //     "http.log",
    //     "ssl.log",
    //     "some/path/weird.log",
    //     "not_a_log.txt"
    // };

    // int num_tests = sizeof(test_paths) / sizeof(test_paths[0]);

    // for (int i = 0; i < num_tests; i++) {
    //     LogType t = get_type((char*)test_paths[i]);
    //     printf("File: %-25s -> Type: %s\n", test_paths[i], logtype_to_str(t));
    // }

    return 0;
}
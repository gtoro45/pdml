#include "zeek_csv.h"
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <errno.h>

// the mutex to allow for safe writing to stdout/file
pthread_mutex_t m;

// the global file descriptor for the 
int csv_fd;

/** 
 * Function that identifies the .log file being read and returns the correct
 * enum type
 * @param path_to_file the string path to the .log file to parse
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


/* msleep(): Sleep for the requested number of milliseconds. */
/**
 * Credit: https://stackoverflow.com/questions/1157209/is-there-an-alternative-sleep-function-in-c-to-milliseconds
 * Comment/Author: caf, edited by George Plaz
 * Answered: 2009, Edited 2019
 * @param msec the number of milliseconds to sleep the program
 */
int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0)
    {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

/**
 * Function that searches for the line AFTER the given timestamp. This
 * is used for when incomplete lines occur in rare cases, and the line is 
 * searched for by string matching with incomplete_line
 * @param fd2 the file descriptor to the log file for reading, passed to maintain position for optimization
 * @param incomplete_line the Zeek-log formatted incomplete line to string match in the file
 * @param prev_line the Zeek-log formatted previous line to identify in the file
 */
char* get_lost_line(int fd2, char* incomplete_line, char* prev_line) {
    // Normalize prev_line: remove trailing newline if present
    char *prev_line_norm = NULL;                                                                // <-- **GPT Modified**
    if (prev_line != NULL) {                                                                    // <-- **GPT Modified**
        size_t len = strlen(prev_line); // safe because prev_line != NULL
        // make a local copy to avoid mutating caller memory unexpectedly
        prev_line_norm = malloc(len + 1);                                                       // <-- **GPT Modified**
        if (prev_line_norm == NULL) {                                                           // <-- **GPT Modified**
            fprintf(stderr, "Memory allocation failed in get_lost_line (prev_line_norm)\n");    // <-- **GPT Modified**                                                                     // <-- **GPT Modified**
            exit(1);    // can't do search safely
        }
        strcpy(prev_line_norm, prev_line);                                                      // <-- **GPT Modified**
        if (len > 0 && prev_line_norm[len - 1] == '\n') {                                       // <-- **GPT Modified**
            prev_line_norm[len - 1] = '\0';               // remove trailing newline
        }
    }
    else {
        printf("Previous line NULL\n");
        return NULL;
    }

    // read char by char, slow and steady (line by line parsing)
    // this is slow and will need to be replaced with something else later
    int n;
    char c;
    char line_buf[EXTRACTION_LINE_SIZE];
    int line_buf_idx = 0;
    bool found_prev = false;

    // read 1 byte at a time
    while((n = read(fd2, &c, sizeof(char))) > 0) {
        // end of line --> check
        if(c == '\n') {
            // null terminate
            line_buf[line_buf_idx] = '\0';

            // check if this line matches the previous line
            if(!found_prev) {
                if(prev_line != NULL && strcmp(line_buf, prev_line_norm) == 0) {
                    found_prev = true;
                }
            }
            else {
                // check if incomplete_line exists as a substring of another --> match if so
                if(incomplete_line != NULL && strstr(line_buf, incomplete_line)) {
                    char* result = malloc(line_buf_idx + 1);
                    if(result == NULL) {
                        fprintf(stderr, "Memory allocation failed in get_lost_line (result)\n"); 
                        free(prev_line_norm); 
                        exit(1);
                    }
                    strcpy(result, line_buf);
                    free(prev_line_norm);
                    return result;
                }
                else {
                    break;  // we only check once after prev_line is found
                }
            }

            // no match --> reset to next line
            line_buf_idx = 0;
        }
        else {
            // Building up the line
            if(line_buf_idx < EXTRACTION_LINE_SIZE - 1) {
                line_buf[line_buf_idx] = c;
                line_buf_idx++;
            }
        }
    }

    free(prev_line_norm);
    return NULL;
}

/**
 * Function that attempts to open the log file specified by path. This function
 * polls the file every second for 60 seconds, after which it will timeout
 * @param path the file to open
 * @return the file descriptor to the file
 */
int open_file_with_retry(char* path) {
    int fd;
    int timeout = 0;
    while((fd = open(path, O_RDONLY)) < 0) {
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
    return fd;
}

/**
 * Function that creates the csv buffer file that the format function writes to and
 * is read by the Data Analysis portion of the program. 
 * @param path the path to save the buffer to
 * @return the file descriptor to the file
 */
int open_csv(char* path) {
    int fd;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXO);
    if(fd < 0) {
        perror("csv file could not be created");
        exit(1);
    }
    return fd;
}

/**
 * Function that checks the tokens for errors in the line. This
 * is usually caused by incomplete lines not caught by the logic in extract_lines().
 * @param tokens the tokens to be verified
 * @param log_type the LogType to check against
 * @return true if erroneous, false otherwise
 */
bool erroneous_tokens(char** tokens, LogType log_type) {
    int count = 0;
    while(tokens[count] != NULL) count++;

    if(count != log_type) {
        printf("[%s]: ERROR - unfinished line: num tokens does not match expected (%d vs. %d)\n", logtype_to_str(log_type), count, log_type);
        return true;
    }
    
    int tok0_len = strlen(tokens[0]);  // most common missing token when (count == logtype)
    int tok1_len = strlen(tokens[1]);  // most common missing token when (count == logtype)
    if(tok0_len != 17) {                        // timestamp floating point length = 17 
        printf("[%s]: ERROR - unfinished line: timestamp corrupted or incomplete (%s)\n", logtype_to_str(log_type), tokens[0]);
        return true;
    } 
    if(tok1_len < 15) {
        printf("[%s]: ERROR - unfinished line: uid corrupted or incomplete (%s)\n", logtype_to_str(log_type), tokens[1]);
        return true;
    }

    return false;
}

/**
 * Function that formats the log file as it is updated live
 */
void* format(void* log_path) {
    // open the file once
    char* path = (char*) log_path;
    int fd = open_file_with_retry(path);

    // mark the kind of log file the function is extracting
    LogType log_type = get_type(path);
    const char* log_type_str = logtype_to_str(log_type);

    // continuously monitor the file for new lines to be added
    char* saved_incomplete = NULL;                      // saved incomplete line from previous iteration
    int header_counter = 0;                             // counter for # of header lines before actual data

    // store the previous line
    char* saved_prev = NULL;

    // open fd2 for search function
    int fd2 = open(path, O_RDONLY);
    if(fd2 < 0) {
        perror("File could not be opened");
        exit(1);
    }

    while(1) {
        LineBuffer new_buf = extract_lines(fd);         // new buffer

        // Skip processing if no new data was read
        if(new_buf.lines == NULL || new_buf.lines[0] == NULL) {
            if(new_buf.incomplete_line) {
                free(new_buf.incomplete_line);
            }
            if(new_buf.lines) {
                free(new_buf.lines);
            }
            continue;
        }

        // check for previously incomplete flags (garbage collection hell)
        if(saved_incomplete != NULL && new_buf.lines[0] != NULL) {
            /* -- Concatenation Logic --*/
            int len1 = strlen(saved_incomplete);                                    // record length of the incomplete line
            int len2 = strlen(new_buf.lines[0]);                                    // record length of the 2nd part of the incomplete line
            char* complete_line = malloc(len1 + len2 + 1);                          // malloc enough space for the new concatenated line
            if (complete_line == NULL) {                                            
                fprintf(stderr, "Memory allocation failed while concatenating incomplete_line\n");
                free(saved_incomplete);
                saved_incomplete = NULL;
                exit(1);
            }
            strcpy(complete_line, saved_incomplete);                                // copy over the incomplete line into the final line (part 1)
            strcat(complete_line, new_buf.lines[0]);                                // concatenate (part 2) of line to end of incomplete line --> complete line atp
            free(new_buf.lines[0]);                                                 // free the 0th element of lines, which contains the 2nd part of the line that we just concatenated
            new_buf.lines[0] = complete_line;                                       // the new complete line is the start of the next chunk of lines
            free(saved_incomplete);                                                 // free the old incomplete line, we are done with it
            saved_incomplete = NULL;
        }

        // update the buffer state between loop iterations
        if(new_buf.incomplete_line != NULL) {
            saved_incomplete = new_buf.incomplete_line;
            new_buf.incomplete_line = NULL;     //transfer ownership
        }

        // parse individual lines
        for(int i = 0; new_buf.lines[i] != NULL; i++) {
            if(header_counter >= 8) {
                // tokenize line
                char** line_tokens = tokenize_full_line(new_buf.lines[i]);

                // convert tokens to csv-readable string
                char* line_csv = csvify_tokens(line_tokens, log_type);

                /**************** THREAD SAFETY: BEGIN MUTEX LOCK ****************/
                pthread_mutex_lock(&m);
                /*****************************************************************/
                
                // erroneous line detection
                bool error = erroneous_tokens(line_tokens, log_type);

                // catch incomplete line and search for it
                if(error) { 
                    printf("[%s]: ERROR - unfinished line: beginning search\n{\n", log_type_str);
                    printf("\tIncomplete line: %s\n", new_buf.lines[i]);
                    clock_t start_time = clock();
                    char** new_tokens = tokenize_full_line(new_buf.lines[i]);                       // tokenize the incomplete line in full, not just to a LogType
                    char* log_line_incomplete = logify_tokens(new_tokens);                          // reconstruct the line in Zeek-log format
                    char* complete_line = get_lost_line(fd2, log_line_incomplete, saved_prev);      // get the complete line in the Zeek log (incomplete + prev line inputs)
                    
                    free(new_buf.lines[i]);                                                         // free the current line in the buffer to replace with the complete line
                    new_buf.lines[i] = malloc(strlen(complete_line) + 1);                           // malloc enough space for the complete line
                    if(new_buf.lines[i] == NULL) {
                        fprintf(stderr, "Memory allocation failed while reallocating new_buf.lines[i] for the incomplete line");
                        exit(1);
                    }
                    strcpy(new_buf.lines[i], complete_line);                                        // copy the complete line into the current line
                    free_tokens(line_tokens);                                                       // free the incomplete tokens to place the new tokens
                    line_tokens = tokenize_full_line(new_buf.lines[i]);                             // tokenize the new, complete line which is now stored at lines[i]
                    free(line_csv);                                                                 // free the previous csv'd line to make the new csv line
                    line_csv = csvify_tokens(line_tokens, log_type);                                          // convert new tokens to CSV-readable string

                    clock_t end_time = clock();
                    double cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
                    printf("\tLogified line: %s\n", log_line_incomplete);
                    printf("\tPrevious line: %s\n", saved_prev);
                    printf("\tComplete line: %s\n", complete_line);
                    printf("\tCSV-ified line: %s\n", line_csv);
                    if(complete_line != NULL) {
                        printf("\tLine found!\n");
                    }
                    else {
                        printf("\tLine NOT found!\n");
                    }
                    printf("\tSearch took %f ms to execute\n}\n", cpu_time_used * 1000);

                    // write line to the buffer file
                    int nbytes_w = write(csv_fd, line_csv, strlen(line_csv));
                    if(nbytes_w < 0) {
                        perror("write");
                        exit(1);
                    }

                    free_tokens(new_tokens);
                    free(log_line_incomplete);
                    free(complete_line);
                }
                // handle normal lines
                else {
                    // printf("[%s]: %s", log_type_str, line_csv);
                    // write line to the buffer file
                    int nbytes_w = write(csv_fd, line_csv, strlen(line_csv));
                    if(nbytes_w < 0) {
                        perror("write");
                        exit(1);
                    }
                }
                fflush(stdout);
                
                /*****************************************************************/
                pthread_mutex_unlock(&m);
                /***************** THREAD SAFETY: END MUTEX LOCK *****************/
                
                // free tokens and line as csv
                free_tokens(line_tokens);
                free(line_csv);

                // save the current line as the last line of the next iteration
                if(saved_prev != NULL) {
                    free(saved_prev);
                }
                saved_prev = malloc(strlen(new_buf.lines[i]) + 1);
                if(saved_prev == NULL) {
                    fprintf(stderr, "Memory allocation failed while saving previous line");
                    exit(1);
                }
                strcpy(saved_prev, new_buf.lines[i]);
            }
            else {
                if(header_counter == 7) {
                    // ensure previous line is never empty
                    saved_prev = malloc(strlen(new_buf.lines[i]) + 1);
                    if(saved_prev == NULL) {
                        fprintf(stderr, "Memory allocation failed while saving previous line");
                        exit(1);
                    }   
                    strcpy(saved_prev, new_buf.lines[i]);
                }
                header_counter++;
            }
        }
        free_lines(new_buf.lines);
        
        // prevent 100% CPU usage
        msleep(50);
    }
    

    // close the file upon loop exit
    close(fd);
    close(fd2);
}

/* Local Main Function */
int main() {
    // create the csv file buffer
    csv_fd = open_csv("../buf/demo_buf.csv");   // these paths are relative to pdml/bin/

    // set up the format() threads
    pthread_mutex_init(&m, NULL);

    pthread_t thread1;
    // pthread_t thread2;
    // pthread_t thread3;
    // pthread_t thread4;

    if(pthread_create(&thread1, NULL, format, "../train_test_data/demo/conn.log") < 0) {    // these paths are relative to pdml/bin/
        perror("pthread_create");
    }
    // if(pthread_create(&thread2, NULL, format, "../src/tests/dns.log") < 0) {
    //     perror("pthread_create");
    // }
    // if(pthread_create(&thread3, NULL, format, "../src/tests/ssl.log") < 0) {
    //     perror("pthread_create");
    // }
    // if(pthread_create(&thread4, NULL, format, "../src/tests/weird.log") < 0) {
    //     perror("pthread_create");
    // }
    
    
    pthread_join(thread1, NULL);
    // pthread_join(thread2, NULL);
    // pthread_join(thread3, NULL);
    // pthread_join(thread4, NULL);

    pthread_mutex_destroy(&m);

    return 0;
}

/* Cluster Main Function */
// int main(int argc, char* argv[]) {
//     if(argc <= 1) {
//         perror("Missing path argument to log files");
//         exit(1);
//     }
//     char* folder_path = argv[1];
//     char* module_type = argv[2];

//     // Build the log file paths
//     char conn_path[256];
//     char dns_path[256];
//     char http_path[256];
//     char ssl_path[256];
//     char weird_path[256];
    
//     switch(module_type) {
//         case "daemon-logs": {
//             snprintf(conn_path, sizeof(conn_path), "%s/conn.log", folder_path);
//             snprintf(dns_path, sizeof(conn_path), "%s/dns.log", folder_path);
//             snprintf(http_path, sizeof(conn_path), "%s/http.log", folder_path);
//             snprintf(ssl_path, sizeof(conn_path), "%s/ssl.log", folder_path);
//             snprintf(weird_path, sizeof(conn_path), "%s/weird.log", folder_path);
//             break;
//         }

//         case "zeek-logs-camera": {
//             snprintf(conn_path, sizeof(conn_path), "%s/conn.log", folder_path);
//             snprintf(dns_path, sizeof(conn_path), "%s/dns.log", folder_path);
//             snprintf(http_path, sizeof(conn_path), "%s/http.log", folder_path);
//             snprintf(ssl_path, sizeof(conn_path), "NULL");
//             snprintf(weird_path, sizeof(conn_path), "%s/weird.log", folder_path);
//             break;
//         }

//         case "zeek-logs-lidar": {
//             snprintf(conn_path, sizeof(conn_path), "%s/conn.log", folder_path);
//             snprintf(dns_path, sizeof(conn_path), "%s/dns.log", folder_path);
//             snprintf(http_path, sizeof(conn_path), "NULL");
//             snprintf(ssl_path, sizeof(conn_path), "NULL");
//             snprintf(weird_path, sizeof(conn_path), "%s/weird.log", folder_path);
//             break;
//         }

//         case "zeek-logs-nginx": {
//             snprintf(conn_path, sizeof(conn_path), "%s/conn.log", folder_path);
//             snprintf(dns_path, sizeof(conn_path), "%s/dns.log", folder_path);
//             snprintf(http_path, sizeof(conn_path), "%s/http.log", folder_path);
//             snprintf(ssl_path, sizeof(conn_path), "%s/ssl.log", folder_path);
//             snprintf(weird_path, sizeof(conn_path), "%s/weird.log", folder_path);
//             break;
//         }
//     }

//     printf("Paths found: \n");
//     printf("\t%s\n", conn_path); 
//     printf("\t%s\n", dns_path); 
//     printf("\t%s\n", http_path); 
//     printf("\t%s\n", ssl_path); 
//     printf("\t%s\n", weird_path);

//     // Launch the threads on the files
//     // TODO

// }


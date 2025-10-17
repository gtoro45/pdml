#include "zeek_csv.h"

const char* logtype_to_str(LogType type) {
    switch (type) {
        case CONN:  return "CONN";
        case DNS:   return "DNS";
        case HTTP:  return "HTTP";
        case SSL:   return "SSL";
        case WEIRD: return "WEIRD";
        default:    return "UNKNOWN";
    }
}

LineBuffer extract_lines(int fd) {
    // read file into large buffer (in chunks) to minimize syscalls
    char buf[EXTRACTION_BUF_SIZE];
    int n;
    int lines_cap = 64;
    char** lines = malloc(lines_cap * sizeof(char*));
    int line_idx = 0;                           // current index in lines (char**)
    char* incomplete_line = NULL;               // to store the incomplete line
    bool incomplete = false;                    // flag if a read was incomplete (no '\n')
    while((n = read(fd, buf, sizeof(buf))) > 0) {
        /* -- Data Processing -- */
        // read the chunk of data stored in buf
        int line_buf_idx = 0;                       // current index in the line buffer
        char line_buf[EXTRACTION_LINE_SIZE];        // the line buffer
        for(int i = 0; i < n; i++) {
            // identify when a line ends
            if(buf[i] == '\n') {
                // null terminate the string
                line_buf[line_buf_idx] = '\0';

                // grow array if needed
                if(line_idx >= lines_cap) {
                    lines_cap *= 2;
                    lines = realloc(lines, lines_cap * sizeof(char*));
                }

                // allocate the memory for the string on the heap
                // line_buf_idx + 1 = total number of characters (N bytes) in the line
                lines[line_idx] = (char*)malloc(line_buf_idx + 1);   
                memcpy(lines[line_idx], line_buf, line_buf_idx + 1);
                // overwrite previous values
                line_buf_idx = 0;   
                // update the line index
                line_idx++;         
            }
            else {
                line_buf[line_buf_idx] = buf[i];
                line_buf_idx++;
            }

            // EDGE CASE: file was written to mid read(), so final line is incomplete
            // i.e. no "\n" to terminate the line
            if(i == n - 1 && buf[i] != '\n') {
                line_buf[line_buf_idx] = '\0';                          // null terminate the string
                incomplete_line = malloc(line_buf_idx + 1);             // add extra byte for '\0'
                memcpy(incomplete_line, line_buf, line_buf_idx + 1);    // copy over current buffer
                incomplete = true;
            }
        }
    }
    lines[line_idx] = NULL;

    LineBuffer result;
    result.lines = lines;
    result.incomplete_line = incomplete_line;
    result.incomplete_flag = incomplete;

    return result;
}

void free_lines(char** lines) {
    for(int i = 0; lines[i] != NULL; i++) {
        free(lines[i]);
    }
    free(lines);
}

char** tokenize_line(char* line, LogType logfile_type) {
    // declare the formatted line
    char* formatted[EXTRACTION_MAX_TOKENS];
    int formatted_idx = 0;

    // Identify the token columns based on the LogType
    int* log_columns = NULL;
    int num_cols = 0;

    switch (logfile_type) {
        case CONN: {
            static int cols[] = {0, 1, 2, 4, 6, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19};
            log_columns = cols;
            num_cols = sizeof(cols) / sizeof(cols[0]);
            break;
        }
        case DNS: {
            static int cols[] = {0, 1, 2, 4, 6, 8, 9, 12, 13, 14, 15, 21, 22};
            log_columns = cols;
            num_cols = sizeof(cols) / sizeof(cols[0]);
            break;
        }
        case HTTP: {
            static int cols[] = {0, 1, 2, 4, 7, 8, 9, 12, 14, 15, 16, 17, 21, 22, 25, 26, 28, 29};
            log_columns = cols;
            num_cols = sizeof(cols) / sizeof(cols[0]);
            break;
        }
        case SSL: {
            static int cols[] = {0, 1, 2, 4, 7, 8, 9, 14};
            log_columns = cols;
            num_cols = sizeof(cols) / sizeof(cols[0]);
            break;
        }
        case WEIRD: {
            static int cols[] = {0, 1, 2, 4, 6, 7, 8, 9, 10};
            log_columns = cols;
            num_cols = sizeof(cols) / sizeof(cols[0]);
            break;
        }
        default:
            log_columns = NULL;
            num_cols = 0;
            break;
    }
        

    // set up the use of strtok
    char* tmp = line;
    char* tok = strtok(tmp, ZEEK_DELIM);

    // iterate through strtok
    int ind = 0;  //track index of correct columns for current token
    while(tok && formatted_idx < EXTRACTION_MAX_TOKENS) {
        // filter the column 
        bool keep = false;
        for(int k = 0; k < num_cols; k++) {
            if(ind == log_columns[k]) {
                keep = true;
                break;
            }
        }

        // append the token if passed filter
        if(keep) {
            formatted[formatted_idx] = malloc(strlen(tok) + 1);
            if(formatted[formatted_idx] != NULL) {
                strcpy(formatted[formatted_idx], tok);
                formatted_idx++;
            }
        }

        // iterate to the next token via a new strtok() call
        // check that the token exists before adding a "," in between
        // Note: "In subsequent calls, the function expects 
        //        a null pointer and uses the position right 
        //        after the end of the last token as the new 
        //        starting location for scanning" (Docs)
        tok = strtok(NULL, ZEEK_DELIM);
        ind++;
    }
 
    
    // return heap allocated copy without any extra malloc'd bytes
    // that came form unused space from EXTRACTION_MAX_TOKENS
    // formatted_idx + 1 is for NULL termination
    char** result = malloc((formatted_idx + 1) * sizeof(char*));
    int i;
    for(i = 0; i < formatted_idx; i++) {
        result[i] = formatted[i];
    }

    // terminate the array of tokens
    result[i] = NULL; 

    return result;
}

void free_tokens(char** tokens) {
    for(int i = 0; tokens[i] != NULL; i++) {
        free(tokens[i]);
    }
    free(tokens);
}

char* csvify_tokens(char** tokens) {
    char* result = NULL;
    for(int i = 0; tokens[i] != NULL; i++) {
        int tok_len = strlen(tokens[i]);
        if(i == 0) {
            result = malloc((tok_len + 2) * sizeof(char));      // +2 for separator AND '\0'
            strcpy(result, tokens[0]);
        }
        else {
            int curr_len = strlen(result);
            result = realloc(result, curr_len + tok_len + 2);   // +2 for separator AND '\0'
            strcat(result, tokens[i]);
        }

        // append ','
        if(tokens[i + 1] != NULL) {     
            strcat(result, ",");
        }
        // append '\n' 
        else {                      
            strcat(result, "\n");
        }
    }   

    return result;
}


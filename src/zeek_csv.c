#include "zeek_csv.h"

char** extract_lines(int fd) {
    // read file into large buffer (in chunks) to minimize syscalls
    char buf[EXTRACTION_BUF_SIZE];
    int n;
    int lines_cap = 64;
    char** lines = malloc(lines_cap * sizeof(char*));
    int line_idx = 0;                           // current index in lines (char**)
    while((n = read(fd, buf, sizeof(buf))) > 0) {
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
                off_t after = lseek(fd, -(line_buf_idx), SEEK_CUR);
                printf("fd after lseek: %lld\n", (long long)after);
            }
        }
    }

    lines[line_idx] = NULL;

    return lines;
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

    // set up the use of strtok
    char* tmp = line;
    char* tok = strtok(tmp, ZEEK_DELIM);

    // iterate through strtok
    while(tok && formatted_idx < EXTRACTION_MAX_TOKENS) {
        // Filter the token
        // TODO
        
        // append the token
        formatted[formatted_idx] = malloc(strlen(tok) + 1);
        strcpy(formatted[formatted_idx], tok);
        formatted_idx++;

        // iterate to the next token via a new strtok() call
        // check that the token exists before adding a "," in between
        // Note: "In subsequent calls, the function expects 
        //        a null pointer and uses the position right 
        //        after the end of the last token as the new 
        //        starting location for scanning" (Docs)
        tok = strtok(NULL, ZEEK_DELIM);
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
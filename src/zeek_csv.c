#include "zeek_csv.h"


char** tokenize_lines(char* log_path) {
    // open the file
    int fd = open(log_path, "r");
    if(fd != 0) {
        perror("File [%s] could not be opened", log_path);
        exit(1);
    }
    
    // read file into large buffer to minimize syscalls
    char buf[TOKENIZER_BUF_SIZE];
    int n;
    char** lines;
    while((n = read(fd, buf, sizeof(buf))) > 0) {
        for(int i = 0; i < n; i++) {
            // identify when a line ends
            if(buf[i] == '\n') {
                //TODO
            }
            else {
                
            }
        }
    }

    return lines;
}
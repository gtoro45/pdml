/**
 * This library contians methods to convert Zeek log files into CSVs,
 * and then from CSVs to one main table for ML input
 */

#ifndef CSV_H_
#define CSV_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <poll.h>
#include <errno.h>
#include <time.h>

#define EXTRACTION_BUF_SIZE 65536   // 64k buffer for very large log files
#define EXTRACTION_MAX_TOKENS 256   // max number of tokens in a zeek log line
#define EXTRACTION_LINE_SIZE 1024   // 1k line buffer for parsing 
#define ZEEK_DELIM "\x09"

/**
 * enum identifying the key logfile types to be processed by the program.
 * Each enum holds a value equal to the number of columns each logfile has.
 */
typedef enum {
    CONN = 21,  // in extracted, not training
    DNS = 24,
    HTTP = 30,
    SSL = 18,
    WEIRD = 11,
    UNKNOWN = -1
} LogType;

const char* logtype_to_str(LogType type);

/**
 * struct that holds multi-line information and state from read() calls
 * that may be incomplete
 * @param lines dynamic array of lines read from Zeek log file at a given instant
 * @param incomplete_line stores an incomplete, non-'\n' terminated line
 * @param incomplete_flag flag if incomplete_line is not NULL
 */
typedef struct {
    char** lines;
    char* incomplete_line;
    bool incomplete_flag;
} LineBuffer;


/**
 * Extract the lines of the given log file into a LineBuffer struct
 * @param fd The file descriptor pointing to the log file to be opened
 * NOTE: THIS FUNCTION'S RETURN IS ALLOCATED MEMORY AND MUST BE FREED
 */
LineBuffer extract_lines(int fd);

/**
 * free the malloc'd lines char** from extract_lines()
 */
void free_lines(char** lines);

/**
 * Takes a space-separated line from a Zeek log file and returns
 * a tokenized version of the line, as an array of strings. Only certain
 * features are extracted based on the LogType
 * @param line The extracted line from the Zeek log file; must be a malloc'd line 
 * @param logfile_type The type of log file being processed
 * @note THIS FUNCTION'S RETURN IS ALLOCATED MEMORY AND MUST BE FREED
 * @deprecated This function has been replaced with tokenize_full_line(), with
 * specific features being extracted in Python
 */
char** tokenize_line(char* line, LogType logfile_type);

/**
 * Takes a space-separated line from a Zeek log file and returns
 * a tokenized version of the line, as an array of strings. All column
 * data is extracted
 * @param line The extracted line from the Zeek log file; must be a malloc'd line 
 * @note THIS FUNCTION'S RETURN IS ALLOCATED MEMORY AND MUST BE FREED
 */
char** tokenize_full_line(char* line);

/**
 * free the malloc'd tokens char** from tokenize_line()
 */
void free_tokens(char** tokens);

/**
 * Take the tokens generate by free_tokens and return a single,
 * csv-formatted string
 * @param tokens The tokens returned by tokenize_line()
 * @note THIS FUNCTION'S RETURN IS ALLOCATED MEMORY AND MUST BE FREED
 */
char* csvify_tokens(char** tokens, LogType log_type);


/** 
 * Opposite function of csvify_tokens() --> return tokens to
 * Zeek-formatted line. This will be used for reverse searching for corrupted strings
 * @param tokens The tokens returned by tokenize_line()
 * @note THIS FUNCTION'S RETURN IS ALLOCATED MEMORY AND MUST BE FREED
 */
char* logify_tokens(char** tokens);

#endif
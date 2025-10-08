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

#define EXTRACTION_BUF_SIZE 65536   // 64k buffer for very large log files
#define EXTRACTION_LINE_SIZE 1024   // 1k line buffer for parsing 
#define ZEEK_DELIM "\x09"

// TODO
// enum LogType {
    
// }


/**
 * Extract the lines of the given log file into a char** (2D array)
 * extract_lines[0]:    contains the column information
 * extract_lines[:len]: contains the data as space separated strings
 * NOTE: THIS FUNCTION'S RETURN IS ALLOCATED MEMORY AND MUST BE FREED
 */
char** extract_lines(char* log_path);

/**
 * Extract the most recent line from a live zeek extraction session
 */
char* extract_latest_line(char* log_path);

/**
 * Takes a space-separated line from a Zeek log file and returns
 * a csv-formatted, comma-delimited line 
 * @param line The extracted line from the Zeek log file; must be a malloc'd line 
 * @note THIS FUNCTION'S RETURN IS ALLOCATED MEMORY AND MUST BE FREED
 */
char* csvify_line(char* line);




#endif
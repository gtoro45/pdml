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
#define TOKENIZER_BUF_SIZE 4096


/**
 * Tokenize the lines of the given log file into a char** (2D array)
 * tokenize_lines[0]:    contains the column information
 * tokenize_lines[:len]: contains the data  
 */
char** tokenize_lines(char* log_path);




#endif
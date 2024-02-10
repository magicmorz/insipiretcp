#ifndef CLI_UTILS_H
#define CLI_UTILS_H

#include <getopt.h>

// Define a structure to hold command-line options
typedef struct {
    char *interface;
    int port;
    int num_packets;
    FILE *fptr;   
} CommandLineOptions;

// Function declarations
void print_help();
void process_options(int argc, char *argv[], CommandLineOptions *options);

#endif

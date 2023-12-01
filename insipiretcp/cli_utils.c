#include <stdio.h>
#include <stdlib.h>
#include "cli_utils.h"
#include "socket_utils.h"

void print_help()
{
    printf("Usage: ./sniffer -i [INTERFACE] [OPTIONS]\n");
    printf("  -i, --interface    Set the network interface\n");
    printf("  -p, --port         Set the port number\n");
    printf("  -n, --num_packets  Set the number of packets to sniff\n");
    printf("  -h, --help         Display this help message\n");
}

void process_options(int argc, char *argv[], CommandLineOptions *options)
{
    // Initialize options to default values
    options->interface = NULL;
    options->port = -1;
    options->num_packets = -1;

    // Define long options
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"port", required_argument, 0, 'p'},
        {"num_packets", required_argument, 0, 'n'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0} // Required at the end of the array
    };

    int option;
    int option_index = 0;

    while ((option = getopt_long(argc, argv, "i:p:n:h", long_options, &option_index)) != -1)
    {
        switch (option)
        {
        case 'i':
            if (isInterfaceValid(optarg))
            {
                printf("Interface %s is valid.\n", optarg);
                options->interface = optarg;
            }
            else
            {
                fprintf(stderr, "Interface %s is not valid or does not exist.\n", optarg);
                exit(EXIT_FAILURE);
            }
            break;
        case 'p':
            options->port = atoi(optarg);
            break;
        case 'n':
            options->num_packets = atoi(optarg);
            if ((options->num_packets) <= 0)
            {
                fprintf(stderr, "number of packet (-n) has to be greater than 0 (%s is invalid).\n", optarg);
                exit(EXIT_FAILURE);
            }

            break;
        case 'h':
            print_help();
            exit(EXIT_SUCCESS);
        case '?':
            // Error handling for unknown options
            fprintf(stderr, "Unknown option: %c\n", optopt);
            print_help();
            exit(EXIT_FAILURE);
        default:
            // Error handling for unexpected cases
            fprintf(stderr, "Unhandled option: %c\n", option);
            print_help();
            exit(EXIT_FAILURE);
        }
    }
    if (options->interface == 0)
    {
        fprintf(stderr, "Missing argument: Interface\n");
        print_help();
        exit(EXIT_FAILURE);
    }

    // Display parsed options
    printf("Network Interface: %s\n", options->interface ? options->interface : "Not set");
    printf("Port Number: %d\n", options->port);
    printf("Number of Packets: %d\n", options->num_packets);
}

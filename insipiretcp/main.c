// main.c
#include "common.h"
#include "socket_utils.h"
#include "debug_utils.h"
#include "cli_utils.h"

int main(int argc, char *argv[])
{

    enable_sudo_debugging();

    CommandLineOptions options;

    process_options(argc, argv, &options);

    // Create a raw socket that will capture all Ethernet protocols
    int raw_socket_descriptor = CreateRawSocket(ETH_P_ALL);

    // Bind the raw socket to the specified network interface
    BindRawSocketToInterface(raw_socket_descriptor, options.interface);

    if (options.num_packets > 0)
    {
        printf("Sniffing %d packets on interface %s...\n", options.num_packets, options.interface);
    }
    else
    {
        printf("Sniffing all packets on interface %s...\n", options.interface);
    }

    // Do sniffing according to provided options
    // TODO make dynamic number of arguments in functino DoSniffing (for optional arguments)
    DoSniffing(raw_socket_descriptor, options.num_packets);

    // Close the socket
    close(raw_socket_descriptor);

    return EXIT_SUCCESS;
}

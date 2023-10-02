// main.c
#include "common.h"
#include "socket_utils.h"
#include "debug_utils.h"

int main(int argc, char *argv[]) {

    enable_sudo_debugging();

    char *interface_name;
    int num_packets;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <num_packets>\n", argv[0]);
        return EXIT_FAILURE;
    }
    // Get interface name and number of packets from user command line input
    interface_name = argv[1];
    if (isInterfaceValid(interface_name)) {
        printf("Interface %s is valid.\n", interface_name);
    } else {
        printf("Interface %s is not valid or does not exist.\n", interface_name);
    }

    // Create a raw socket that will capture all Ethernet protocols
    int raw_socket_descriptor = CreateRawSocket(ETH_P_ALL);

    
    // Bind the raw socket to the specified network interface
    BindRawSocketToInterface(raw_socket_descriptor, interface_name);

    num_packets = atoi(argv[2]);
    printf("Sniffing %d packets on interface %s...\n", num_packets, interface_name);
    
    SniffPackets(raw_socket_descriptor, num_packets);

    // Close the socket
    close(raw_socket_descriptor);

    return EXIT_SUCCESS;
}

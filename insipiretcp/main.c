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


    // Create a raw socket that will capture all Ethernet protocols
    int sockfd = CreateRawSocket(ETH_P_ALL);

    // Get interface name and number of packets from user command line input
    interface_name = argv[1];
    // Bind the raw socket to the specified network interface
    BindRawSocketToInterface(sockfd, interface_name);

    num_packets = atoi(argv[2]);
    printf("Sniffing %d packets on interface %s...\n", num_packets, interface_name);

    SniffPackets(sockfd, num_packets, interface_name);

    // Close the socket
    close(sockfd);

    return EXIT_SUCCESS;
}

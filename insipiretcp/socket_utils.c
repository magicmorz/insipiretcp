// socket_utils.c
#include "common.h"
#include "socket_utils.h"
#define ERROR -1
int CreateRawSocket(int protocol_to_sniff) {
    int sockfd;

    // Create a raw socket with the specified protocol
    // Domain = AF_PACKET (IPv4 communication)
    // type = SOCK_RAW 
    // protocol = provided argument (int protocol_to_sniff)
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(protocol_to_sniff)); 

    if (sockfd == ERROR) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

void BindRawSocketToInterface(int sockfd, char *interface_name) {
    struct sockaddr_ll sll;
    struct ifreq ifr;

    memset(&sll, 0, sizeof(struct sockaddr_ll));
    memset(&ifr, 0, sizeof(struct ifreq));

    // Get the index of the interface
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL); // Capture all Ethernet protocols, endieness (host to network, short)
    sll.sll_ifindex = ifr.ifr_ifindex;

    // Bind the socket to the specified network interface
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) == ERROR) {
        perror("Bind error");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

void PrintPacketInHex(unsigned char *packet, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void SniffPackets(int sockfd, int num_packets, char* interface_name)
{
    for (int i = 0; i < num_packets; i++) {
        unsigned char packet[2048]; // Adjust the size as needed
        int packet_length;

        // Receive a packet
        packet_length = recvfrom(sockfd, packet, sizeof(packet), 0, NULL, NULL);
        if (packet_length == -1) {
            perror("Packet receive error");
            close(sockfd);
            return EXIT_FAILURE;
        }

        printf("Packet %d:\n", i + 1);

        // Print the packet in hexadecimal form
        PrintPacketInHex(packet, packet_length);
    }
}

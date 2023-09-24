// socket_utils.c
#include "common.h"
#include "socket_utils.h"
#define ERROR -1
int CreateRawSocket(int protocol_to_sniff) {
    int sock_desc;

    // Create a raw socket with the specified protocol
    // Domain = AF_PACKET (IPv4 communication)
    // type = SOCK_RAW 
    // protocol = provided argument (int protocol_to_sniff)
    sock_desc = socket(AF_PACKET, SOCK_RAW, htons(protocol_to_sniff)); 

    if (sock_desc == ERROR) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    return sock_desc;
}

void BindRawSocketToInterface(int sock_desc, char *interface_name) {
    struct sockaddr_ll packet_info;
    struct ifreq ifr;

    memset(&packet_info, 0, sizeof(struct sockaddr_ll));
    memset(&ifr, 0, sizeof(struct ifreq));

    // Get the index of the interface
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    if (ioctl(sock_desc, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        close(sock_desc);
        exit(EXIT_FAILURE);
    }

    packet_info.sll_family = AF_PACKET;
    packet_info.sll_protocol = htons(ETH_P_ALL); // Capture all Ethernet protocols, endieness (host to network byte order, short)
    packet_info.sll_ifindex = ifr.ifr_ifindex;

    // Bind the socket to the specified network interface
    if (bind(sock_desc, (struct sockaddr *)&packet_info, sizeof(struct sockaddr_ll)) == ERROR) {
        perror("Bind error");
        close(sock_desc);
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

void SniffPackets(int sockfd, int num_packets)
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

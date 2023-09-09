// sniffer.c
#include "common.h"
#include "sniffer.h"

int CreateRawSocket(int protocol_to_sniff) {
    int sockfd;

    // Create a raw socket with the specified protocol
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(protocol_to_sniff));

    if (sockfd == -1) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

void BindRawSocketToInterface(int sockfd, char *interface_name) {
    struct sockaddr_ll sll; // "ll" stands for "link layer" (aka "layer 2" or "data link layer")
    struct ifreq ifr; // interface requst

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
    sll.sll_protocol = htons(ETH_P_ALL); // Capture all Ethernet protocols
    sll.sll_ifindex = ifr.ifr_ifindex;

    // Bind the socket to the specified network interface
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) == -1) {
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

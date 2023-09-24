// socket_utils.c
#include "common.h"
#include "socket_utils.h"
#include "protocol_support.h"
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

int GetInterfaceIndex(int sock_desc, char *interface_name)
{
    struct ifreq interface_request;
    memset(&interface_request, 0, sizeof(struct ifreq));
    strncpy(interface_request.ifr_name, interface_name, IFNAMSIZ - 1);
    // ioctl will make interface_request.ifr_ifindex filled by the kernel 
    if (ioctl(sock_desc, SIOCGIFINDEX, &interface_request) == -1) {   
        perror("Error getting interface index");
        close(sock_desc);
        exit(EXIT_FAILURE);
    }
    return interface_request.ifr_ifindex;
}   

void BindRawSocketToInterface(int sock_desc, char *interface_name) {
    struct sockaddr_ll socket_info;
    memset(&socket_info, 0, sizeof(struct sockaddr_ll));
   
    socket_info.sll_family = AF_PACKET;
    socket_info.sll_protocol = htons(ETH_P_ALL); // Capture all Ethernet protocols, endieness (host to network byte order, short)
    socket_info.sll_ifindex = GetInterfaceIndex(sock_desc, interface_name);

    // Bind the socket to the specified network interface
    if (bind(sock_desc, (struct sockaddr *)&socket_info, sizeof(struct sockaddr_ll)) == ERROR) {
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

        ParseEthernet(packet, packet_length);
    }
}

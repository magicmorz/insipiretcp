#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

// Define the struct sockaddr_ll manually
struct sockaddr_ll
{
    unsigned short sll_family;   // AF_PACKET
    unsigned short sll_protocol; // Protocol (e.g., ETH_P_ALL for all Ethernet protocols)
    int sll_ifindex;             // Interface index
    unsigned short sll_hatype;   // Header type (e.g., ARPHRD_ETHER for Ethernet)
    unsigned char sll_pkttype;   // Packet type (e.g., PACKET_OUTGOING for outgoing packets)
    unsigned char sll_halen;     // Length of hardware address
    unsigned char sll_addr[8];   // Hardware address (MAC address)
};

// Function to create a raw socket
int CreateRawSocket(int protocol_to_sniff)
{
    int sockfd;

    // Create a raw socket with the specified protocol
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(protocol_to_sniff));

    if (sockfd == -1)
    {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

// Function to bind the raw socket to a specific network interface
void BindRawSocketToInterface(int sockfd, char *interface_name)
{
    struct sockaddr_ll sll;
    struct ifreq ifr;

    memset(&sll, 0, sizeof(struct sockaddr_ll));
    memset(&ifr, 0, sizeof(struct ifreq));

    // Get the index of the interface
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1)
    {
        perror("SIOCGIFINDEX");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL); // Capture all Ethernet protocols
    sll.sll_ifindex = ifr.ifr_ifindex;

    // Bind the socket to the specified network interface
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) == -1)
    {
        perror("Bind error");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

// Function to print a packet in hexadecimal form
void PrintPacketInHex(unsigned char *packet, int length)
{
    for (int i = 0; i < length; i++)
    {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("\n");
}

int main(int argc, char *argv[])
{

    // -----------start of sudo debug enabling
    /*
    The sole purprose of this code is to enable debugging with sudo in vscode.
    In order to make it work, make the following steps:
    1. add to launch.json:
        {
        "miDebuggerPath": "${workspaceFolder}/gdb_root.sh"
        }
    2. create file gdb_root.sh:
        #!/bin/bash
        SELF_PATH=$(realpath -s "$0")

        if [[ "$SUDO_ASKPASS" = "$SELF_PATH" ]]; then
        zenity --password --title="$1"
        else
        exec env SUDO_ASKPASS="$SELF_PATH" sudo -A /usr/bin/gdb $@
        fi
    3.  chmod +x gdb_root.sh
    4.  add the following code block to main with the needed #include-s
    */
    // accept signal from VSCode for pausing/stopping
    char *sudo_uid = getenv("SUDO_UID");
    if (sudo_uid)
        setresuid(0, 0, atoi(sudo_uid));

    printf("uid = %d\n", getuid());
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <interface> <num_packets>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // ----------- end of sudo debug enabling 


    char *interface_name = argv[1];
    int num_packets = atoi(argv[2]);

    // Create a raw socket
    int sockfd = CreateRawSocket(ETH_P_ALL);

    // Bind the raw socket to the specified network interface
    BindRawSocketToInterface(sockfd, interface_name);

    printf("Sniffing %d packets on interface %s...\n", num_packets, interface_name);

    for (int i = 0; i < num_packets; i++)
    {
        unsigned char packet[2048]; // Adjust the size as needed
        int packet_length;

        // Receive a packet
        packet_length = recvfrom(sockfd, packet, sizeof(packet), 0, NULL, NULL);
        if (packet_length == -1)
        {
            perror("Packet receive error");
            close(sockfd);
            return EXIT_FAILURE;
        }

        printf("Packet %d:\n", i + 1);

        // Print the packet in hexadecimal form
        PrintPacketInHex(packet, packet_length);
    }

    // Close the socket
    close(sockfd);

    return EXIT_SUCCESS;
}

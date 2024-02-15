// socket_utils.c
#include "common.h"
#include "socket_utils.h"
#include "protocol_support.h"
#include "general_utils.h"
#include "capture/pcapng/pcapng.h"
#include "file/file_pcapng/file_pcapng_utils.h"

#define ERROR -1
#define LINKTYPE_ETHERNET 1

int CreateRawSocket(int protocol_to_sniff)
{
    int sock_desc;

    // Create a raw socket with the specified protocol
    // Domain = AF_PACKET (IPv4 communication)
    // type = SOCK_RAW
    // protocol = provided argument (int protocol_to_sniff)
    sock_desc = socket(AF_PACKET, SOCK_RAW, htons(protocol_to_sniff));

    if (sock_desc == ERROR)
    {
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
    if (ioctl(sock_desc, SIOCGIFINDEX, &interface_request) == -1)
    {
        perror("Error getting interface index");
        close(sock_desc);
        exit(EXIT_FAILURE);
    }
    return interface_request.ifr_ifindex;
}

void BindRawSocketToInterface(int sock_desc, char *interface_name)
{
    struct sockaddr_ll socket_info;
    memset(&socket_info, 0, sizeof(struct sockaddr_ll));

    socket_info.sll_family = AF_PACKET;
    socket_info.sll_protocol = htons(ETH_P_ALL); // Capture all Ethernet protocols, endieness (host to network byte order, short)
    socket_info.sll_ifindex = GetInterfaceIndex(sock_desc, interface_name);

    // Bind the socket to the specified network interface
    if (bind(sock_desc, (struct sockaddr *)&socket_info, sizeof(struct sockaddr_ll)) == ERROR)
    {
        perror("Bind error");
        close(sock_desc);
        exit(EXIT_FAILURE);
    }
}

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

int isInterfaceValid(const char *interfaceName)
{
    // Use if_nametoindex to check if the interface name is valid
    unsigned int index = if_nametoindex(interfaceName);

    if (index != 0)
    {
        return 1; // Interface is valid
    }
    else
    {
        return 0; // Interface is not valid or does not exist
    }
}

int DoSniffing(int sockfd, int num_packets)
{
    char timestamp[30]; // Adjust the size as needed

    PCAPNG *capture = createPCAPNG();
    if (capture == NULL)
    {
        fprintf(stderr, "Failed to create PCAPNG structure\n");
        return EXIT_FAILURE;
    }

    // Create an Interface Description Block (IDB) for the interface
    IDB *idb = createIDB(LINKTYPE_ETHERNET); 
    if (idb == NULL)
    {
        fprintf(stderr, "Failed to create IDB\n");
        freePCAPNG(capture); // Free the PCAPNG structure before exiting
        return EXIT_FAILURE;
    }

    // Add the IDB to the PCAPNG structure
    addIDBNode(capture, idb);

    for (int i = 0; (num_packets <= 0) || (i < num_packets); i++)
    {
        unsigned char packet[2048]; // Adjust the size as needed
        int packet_length;

        GetTimeStamp(timestamp, sizeof(timestamp));
        printf("Timestamp: %s\n", timestamp);

        // Receive a packet
        packet_length = recvfrom(sockfd, packet, sizeof(packet), 0, NULL, NULL);
        if (packet_length == -1)
        {
            perror("Packet receive error");
            close(sockfd);
            return EXIT_FAILURE;
        }
        // Create a new EPB for the captured packet
        EPB *epb = createEPB(1, packet_length, packet_length, packet);
        if (epb == NULL)
        {
            fprintf(stderr, "Failed to create EPB for packet %d\n", i + 1);
            // Free memory allocated for previously captured packets
            freePCAPNG(capture);
            return EXIT_FAILURE;
        }

        // Add the EPB to the PCAPNG structure
        addEPBNode(capture, epb);

        printf("Packet %d:\n", i + 1);

        // Print the packet in hexadecimal form
        PrintPacketInHex(packet, packet_length);

        PacketMetadata packet_metadata = {0, 0, 0, 0, 0, 0, 0};
        ParseLayer2(packet, packet_length, &packet_metadata);
        ParseLayer3(packet, packet_length, &packet_metadata);
        if (packet_metadata.layer3_protocol_id == ETH_P_ARP)
        {
            printf("------------ END OF PACKET, ARP ------------\n");
        }

        else if (packet_metadata.layer3_protocol_id == ETH_P_IPV6)
        {
            printf("------------ END OF PACKET, IPv6 ------------\n");
        }

        else if (packet_metadata.number_of_layers >= 4)
        {
            ParseLayer4(packet, packet_length, &packet_metadata);
        }

        else if (packet_metadata.layer4_protocol_id == IPPROTO_TCP)
        {

            if (!ParseData(packet, packet_length))
            {
                printf("------------ END OF PACKET, IP & TCP & NO DATA ------------\n");
            }
            else
            {
                printf("------------ END OF PACKET, IP & TCP & DATA ------------\n");
            }
        }
        else if (packet_metadata.layer4_protocol_id == IPPROTO_UDP)
        {
            if (!ParseData(packet, packet_length))
            {
                printf("------------ END OF PACKET, IP & UDP & NO DATA ------------\n");
            }
            else
            {
                printf("------------ END OF PACKET, IP & UDP & DATA ------------\n");
            }
        }

        else
        {
            printf("------------ END OF PACKET, NOT IP NOT IPv6 NOT ARP ------------\n");
        }
        PrintPacketMetadata(&packet_metadata);
        PrintPacketWithLayers(packet, packet_length, &packet_metadata);
        printf("\n\n");
    }

    printf("DONE PRINTING GARBAGE NOW PRINTING PCAPNG STRUCTURE\n");
    printPCAPNG(capture);
    // Save the PCAPNG structure to a file
    if (savePCAPNGToFile(capture, "output/captured_packets.pcapng") != 0)
    {
        fprintf(stderr, "Failed to save PCAPNG structure to file\n");
        // Free memory allocated for the PCAPNG structure
        freePCAPNG(capture);
        return EXIT_FAILURE;
    }
    freePCAPNG(capture);
    return EXIT_SUCCESS;
}

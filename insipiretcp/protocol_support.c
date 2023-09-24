#include "common.h"
#include "general_utils.h"
void ParseEthernet(unsigned char *packet, int len)
{

    struct ethhdr* ethernet_header;
    if (len>sizeof(ethernet_header))
    {
        ethernet_header = (struct ethhder*)packet;
        PrintInHex("Destination MAC: ", ethernet_header->h_dest, 6);
        printf("\n");
        PrintInHex("Source MAC: ", ethernet_header->h_source, 6);
        printf("\n");
        PrintInHex("Protocol: ", (void *)&ethernet_header->h_proto, 2);
        printf("\n");
    }
    else
    {
        perror("Packet is too short for Ethernet\n");
    }
    

}
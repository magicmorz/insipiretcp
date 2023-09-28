#include "common.h"
#include "general_utils.h"
void ParseEthernet(unsigned char *packet, size_t len)
{

    struct ethhdr *ethernet_header;
    if (len > sizeof(ethernet_header))
    {
        ethernet_header = (struct ethhdr *)packet;
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

void ParseIP(unsigned char *packet, size_t len)
{
    struct ethhdr *ethernet_header;
    struct iphdr *ip_header;

    /* First check if the packet contains an IP header using the Ethernet header */

    ethernet_header = (struct ethhdr *)packet;
    if (ntohs(ethernet_header->h_proto) == ETH_P_IP)
    {
        /* The IP header is after the Ethernet header */
        if (len >= (sizeof(struct ethhdr) + sizeof(struct iphdr)))
        {
            ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

            /* Convert IP addresses from network byte order to host byte order */
            struct in_addr src_addr, dest_addr;
            src_addr.s_addr = ip_header->saddr;
            dest_addr.s_addr = ip_header->daddr;

            /* Print the source and destination IP address */
            printf("Destination IP address: %s\n", inet_ntoa(dest_addr));
            printf("Source IP address: %s\n", inet_ntoa(src_addr));
            printf("tos: %u\n", ip_header->tos);
            printf("total length: %hu\n", ntohs(ip_header->tot_len));
            printf("id: %hu\n", ntohs(ip_header->id));
            printf("fragment offset: %hu\n", ntohs(ip_header->frag_off));
            printf("ttl: %u\n", ip_header->ttl);
            printf("protocol is: %u\n", ip_header->protocol);
            printf("checksum is: %04x\n", ip_header->check);
        }
        else
        {
            perror("IP packet does not have full header");
        }
    }
    else
    {
        /* Not an IP packet */
    }
}

void ParseTCP(unsigned char *packet, size_t len)
{
    struct ethhdr *ethernet_header;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    /* Check if enough bytes are there for TCP header */
    if (len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
    {
        /* Do all the checks: 1. Is it an IP packet? 2. Is it TCP? */
        ethernet_header = (struct ethhdr *)packet;

        if (htons(ethernet_header->h_proto) == ETH_P_IP)
        {
            ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

            if (ip_header->protocol == IPPROTO_TCP)
            {
                tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);

                /* Print the Dest and Src ports */
                printf("Source Port: %d\n", ntohs(tcp_header->source));
                printf("Dest Port: %d\n", ntohs(tcp_header->dest));
            }
            else
            {
                printf("Not a TCP packet");
            }
        }
        else
        {
            printf("Not an IP packet\n");
        }
    }
}
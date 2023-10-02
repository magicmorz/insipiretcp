#include "common.h"
#include "general_utils.h"
#include "socket_utils.h"
void ParseEthernet(unsigned char *packet, size_t len)
{

    struct ethhdr *ethernet_header;
    if (len > sizeof(ethernet_header))
    {
        ethernet_header = (struct ethhdr *)packet;
        printf("---- Ethernet ----- \n");
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

int ParseIP(unsigned char *packet, size_t len)
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
            printf("---- IPv4 ----- \n");
            printf("Destination IP address: %s\n", inet_ntoa(dest_addr));
            printf("Source IP address: %s\n", inet_ntoa(src_addr));
            printf("tos: %u\n", ip_header->tos);
            printf("total length: %hu\n", ntohs(ip_header->tot_len));
            printf("id: %hu\n", ntohs(ip_header->id));
            printf("fragment offset: %hu\n", ntohs(ip_header->frag_off));
            printf("ttl: %u\n", ip_header->ttl);
            printf("protocol is: %u\n", ip_header->protocol);
            printf("checksum is: %04x\n", ip_header->check);
            return 1;
        }
        else
        {
            perror("IP packet does not have full header");
            return -1;
        }
    }
    else
    {
        /* Not an IP packet */
        return -1;
    }
}

int ParseIPv6(unsigned char *packet, size_t len)
{
    // IPv6 Header Structure
    struct ipv6hdr
    {
        // 4-bit Version, 8-bit Traffic Class, 20-bit Flow Label
        uint32_t version_tc_fl;     // Version, Traffic Class, Flow Label
        uint16_t payload_length;    // 16-bit Payload Length
        uint8_t next_header;        // 8-bit Next Header (Protocol)
        uint8_t hop_limit;          // 8-bit Hop Limit
        uint8_t source_ip[16];      // 128-bit Source IPv6 Address
        uint8_t destination_ip[16]; // 128-bit Destination IPv6 Address
    };

      if (len >= sizeof(struct ipv6hdr)) {
        // Create a pointer to the IPv6 header structure
        const struct ipv6hdr *ipv6_header = (struct ipv6hdr *)(packet + sizeof(struct ethhdr));

        // Extract fields from the IPv6 header structure
        uint8_t version = (ipv6_header->version_tc_fl >> 28) & 0x0F;
        uint8_t traffic_class = (ipv6_header->version_tc_fl >> 20) & 0xFF;
        uint32_t flow_label = ipv6_header->version_tc_fl & 0xFFFFF;
        uint16_t payload_length = ntohs(ipv6_header->payload_length);
        uint8_t next_header = ipv6_header->next_header;
        uint8_t hop_limit = ipv6_header->hop_limit;

        char source_ip_str[INET6_ADDRSTRLEN];
        char dest_ip_str[INET6_ADDRSTRLEN];

        // Convert source and destination IPv6 addresses to strings
        inet_ntop(AF_INET6, ipv6_header->source_ip, source_ip_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, ipv6_header->destination_ip, dest_ip_str, INET6_ADDRSTRLEN);

        // Print IPv6 header information
        printf("---- IPv6 Header ----\n");
        printf("Version: %u\n", version);
        printf("Traffic Class: %u\n", traffic_class);
        printf("Flow Label: %u\n", flow_label);
        printf("Payload Length: %u\n", payload_length);
        printf("Next Header (Protocol): %u\n", next_header);
        printf("Hop Limit: %u\n", hop_limit);
        printf("Source IP: %s\n", source_ip_str);
        printf("Destination IP: %s\n", dest_ip_str);

        return 1;
    } else {
        perror("IPv6 packet is too short");
        return -1;
    }
}

int ParseARP(unsigned char *packet, size_t len)
{

    // Define the ARP structure
    struct arphdr
    {
        __be16 ar_hrd;                  /* format of hardware address   */
        __be16 ar_pro;                  /* format of protocol address   */
        unsigned char ar_hln;           /* length of hardware address   */
        unsigned char ar_pln;           /* length of protocol address   */
        __be16 ar_op;                   /* ARP opcode (command)         */
        unsigned char ar_sha[ETH_ALEN]; /* sender hardware address  */
        unsigned char ar_sip[4];        /* sender IP address          */
        unsigned char ar_tha[ETH_ALEN]; /* target hardware address  */
        unsigned char ar_tip[4];        /* target IP address          */
    };

    struct ethhdr *ethernet_header;
    ethernet_header = (struct ethhdr *)packet;

    struct arphdr *arp_header;

    /* First check if the packet contains an ARP header using the Ethernet header */
    if (ntohs(ethernet_header->h_proto) == ETH_P_ARP)
    {
        /* The ARP header is after the Ethernet header */
        if (len >= (sizeof(struct ethhdr) + sizeof(struct arphdr)))
        {
            arp_header = (struct arphdr *)(packet + sizeof(struct ethhdr));

            printf("---- ARP ----- \n");
            printf("format of hardware address: 0x%04x\n", ntohs(arp_header->ar_hrd));
            printf("format of protocol address: 0x%04x\n", ntohs(arp_header->ar_pro));
            printf("length of hardware address: %d\n", arp_header->ar_hln);
            printf("length of protocol address: %d\n", arp_header->ar_pln);
            printf("ARP opcode (command): 0x%04x\n", ntohs(arp_header->ar_op));
            printf("Sender MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   arp_header->ar_sha[0], arp_header->ar_sha[1],
                   arp_header->ar_sha[2], arp_header->ar_sha[3],
                   arp_header->ar_sha[4], arp_header->ar_sha[5]);
            printf("Sender IP address: %d.%d.%d.%d\n",
                   arp_header->ar_sip[0], arp_header->ar_sip[1],
                   arp_header->ar_sip[2], arp_header->ar_sip[3]);

            printf("Target MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   arp_header->ar_tha[0], arp_header->ar_tha[1],
                   arp_header->ar_tha[2], arp_header->ar_tha[3],
                   arp_header->ar_tha[4], arp_header->ar_tha[5]);
            printf("Target IP address: %d.%d.%d.%d\n",
                   arp_header->ar_tip[0], arp_header->ar_tip[1],
                   arp_header->ar_tip[2], arp_header->ar_tip[3]);

            return 1;
        }
        else
        {
            perror("ARP packet does not have full header");
            return -1;
        }
    }
    else
    {
        /* Not an ARP packet */
        return -1;
    }
}

int ParseTCP(unsigned char *packet, size_t len)
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
                printf("---- TCP ----- \n");
                /* Print the Dest and Src ports */
                printf("Source Port: %d\n", ntohs(tcp_header->source));
                printf("Dest Port: %d\n", ntohs(tcp_header->dest));
                return 1;
            }
            else
            {
                printf("Not a TCP packet\n");
                return -1;
            }
        }
        else
        {
            printf("Not an IP packet\n");
            return -1;
        }
    }
    return -1;
}

int ParseUDP(unsigned char *packet, size_t len)
{
    struct ethhdr *ethernet_header;
    struct iphdr *ip_header;
    struct udphdr *udp_header;

    /* Check if enough bytes are there for TCP header */
    if (len >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
    {
        /* Do all the checks: 1. Is it an IP packet? 2. Is it TCP? */
        ethernet_header = (struct ethhdr *)packet;

        if (htons(ethernet_header->h_proto) == ETH_P_IP)
        {
            ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

            if (ip_header->protocol == IPPROTO_UDP)
            {
                udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);
                printf("---- UDP ----- \n");
                /* Print the Dest and Src ports */
                printf("Source Port: %d\n", ntohs(udp_header->source));
                printf("Dest Port: %d\n", ntohs(udp_header->dest));
                return 1;
            }
            else
            {
                printf("Not a UDP packet\n");
                return -1;
            }
        }
        else
        {
            printf("Not an UDP packet\n");
            return -1;
        }
    }
    return -1;
}

int ParseData(unsigned char *packet, size_t len)
{
    struct iphdr *ip_header;
    unsigned char *data;
    int data_len;

    /* Check if any data is there */
    if (len > (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)))
    {
        ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

        data = (packet + sizeof(struct ethhdr) + ip_header->ihl * 4 + sizeof(struct tcphdr));

        data_len = ntohs(ip_header->tot_len) - ip_header->ihl * 4 - sizeof(struct tcphdr);
        if (data_len)
        {
            printf("---- Data ----- \n");
            printf("Data Length : %d\n", data_len);
            printf("Data : \n");
            PrintPacketInHex(data, data_len);
            printf("\n\n");
            return 1;
        }
        else
        {
            printf("No Data in packet\n");
            return 0;
        }
    }
    else
    {
        printf("No Data in packet\n");
        return 0;
    }
}

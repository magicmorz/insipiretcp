#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include "common.h"
#include "general_utils.h"

void PrintInHex(const char *msg, const unsigned char *p, int len)
{
    printf("%s", msg);
    while (len--)
    {
        printf("%.2X ", *p);
        p++;
    }
    
}

void GetTimeStamp(char *timestamp, size_t timestamp_size) {
    if (timestamp_size < 30) {
        // Ensure there's enough space for the timestamp
        fprintf(stderr, "Timestamp buffer too small\n");
        return;
    }

    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    // Use strftime and localtime correctly
    struct tm *local_time = localtime(&current_time.tv_sec);
    if (local_time == NULL) {
        perror("localtime");
        return;
    }

    // Format the timestamp as "YYYY-MM-DD HH:MM:SS.ssssss"
    strftime(timestamp, timestamp_size, "%Y-%m-%d %H:%M:%S", local_time);

    // Append the microseconds part
    snprintf(timestamp + 19, timestamp_size - 19, ".%06ld", current_time.tv_usec);
}

void PrintLayer (unsigned short protocol_id, int* current_position, unsigned short size_bytes, unsigned char *packet)
{
    // Convert protocol ID to protocol name
        const char *protocol_name = ether_protocol_ntoa(protocol_id);

        if (protocol_name != NULL)
        {
            printf("---- Layer Header %s ----\n", protocol_name);
            for (int i = 0; i < size_bytes; i++)
            {
                printf("%02x ", packet[*current_position]);
                (*current_position)++;
            }
            printf("\n");
        }
        else
        {
            fprintf(stderr, "Unknown protocol ID: 0x%04X\n", protocol_id);
        }
}

// Mapping function for converting protocol ID to string
const char *ether_protocol_ntoa(unsigned short protocol_id)
{
    switch (protocol_id)
    {
    case ETH_P_IP:
        return "IPv4";
    case ETH_P_IPV6:
        return "IPv6";
    case ETH_P_ARP:
        return "ARP";
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    // Add more cases as needed
    default:
        return NULL; // Unknown protocol ID
    }
}

// packet_metadata.h

#ifndef PACKET_METADATA_H
#define PACKET_METADATA_H

#include <netinet/if_ether.h> // for protocol codes

// Define the packet metadata struct
struct PacketMetadata
{
    // Layer 2 information
    unsigned short layer2_protocol_id; // Protocol type at Layer 2 (e.g., Ethernet)
    unsigned short layer2_size_bytes;  // Size of Layer 2 in bytes

    // Layer 3 information
    unsigned short layer3_protocol_id; // Protocol type at Layer 3
    unsigned short layer3_size_bytes;  // Size of Layer 3 in bytes

    // Layer 4 information
    unsigned short layer4_protocol_id; // Protocol type at Layer 4
    unsigned short layer4_size_bytes;  // Size of Layer 4 in bytes

    // General information
    unsigned short number_of_layers; // amount of OSI layers in the packet
};

// Typedef for convenience
typedef struct PacketMetadata PacketMetadata;

#endif // PACKET_METADATA_H

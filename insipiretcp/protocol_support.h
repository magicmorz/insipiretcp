// protocol_support.h
#ifndef PROTOCOL_SUPPORT_H
#define PROTOCOL_SUPPORT_H

void ParseEthernet(unsigned char *packet, int len);
int ParseIP(unsigned char *packet, int len, PacketMetadata* packet_metadata);
int ParseIPv6(unsigned char *packet, size_t len, PacketMetadata* packet_metadata);
int ParseARP(unsigned char *packet, size_t len, PacketMetadata* packet_metadata);
int ParseTCP(unsigned char *packet, size_t len, PacketMetadata* packet_metadata);
int ParseUDP(unsigned char *packet, size_t len, PacketMetadata* packet_metadata);
int ParseLayer2(unsigned char *packet, size_t packet_length, PacketMetadata *packet_metadata);
int ParseLayer3(unsigned char *packet, size_t packet_length, PacketMetadata *packet_metadata);
int ParseLayer4(unsigned char *packet, size_t packet_length, PacketMetadata *packet_metadata);
void PrintPacketMetadata(const PacketMetadata* packet_metadata);
void PrintPacketWithLayers(unsigned char *packet, int length, const PacketMetadata *packet_metadata);
#endif /* PROTOCOL_SUPPORT_H */
// socket_utils.h
#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <stdio.h>

int CreateRawSocket(int protocol_to_sniff);
void BindRawSocketToInterface(int sockfd, char *interface_name);
void PrintPacketInHex(unsigned char *packet, int length);
int SniffPackets(int sockfd, int num_packets);
int IsIpAndTcpPacket(unsigned char *packet);
int ParseData(unsigned char *packet, size_t len);

#endif /* SOCKET_UTILS_H */

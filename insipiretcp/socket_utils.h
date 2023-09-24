// socket_utils.h
#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <stdio.h>

int CreateRawSocket(int protocol_to_sniff);
void BindRawSocketToInterface(int sockfd, char *interface_name);
void PrintPacketInHex(unsigned char *packet, int length);
void SniffPackets(int sockfd, int num_packets);

#endif /* SOCKET_UTILS_H */

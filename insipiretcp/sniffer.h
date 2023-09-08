// sniffer.h
#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdio.h>

int CreateRawSocket(int protocol_to_sniff);
void BindRawSocketToInterface(int sockfd, char *interface_name);
void PrintPacketInHex(unsigned char *packet, int length);

#endif /* SNIFFER_H */

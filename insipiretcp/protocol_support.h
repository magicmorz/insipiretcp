// protocol_support.h
#ifndef PROTOCOL_SUPPORT_H
#define PROTOCOL_SUPPORT_H

void ParseEthernet(unsigned char *packet, int len);
int ParseIP(unsigned char *packet, int len);
int ParseIPv6(unsigned char *packet, size_t len);
int ParseARP(unsigned char *packet, size_t len);
int ParseTCP(unsigned char *packet, size_t len);
int ParseUDP(unsigned char *packet, size_t len);

#endif /* PROTOCOL_SUPPORT_H */
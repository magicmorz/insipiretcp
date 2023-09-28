// protocol_support.h
#ifndef PROTOCOL_SUPPORT_H
#define PROTOCOL_SUPPORT_H

void ParseEthernet(unsigned char *packet, int len);
void ParseIP(unsigned char *packet, int len);
void ParseTCP(unsigned char *packet, size_t len);

#endif /* PROTOCOL_SUPPORT_H */
// protocol_support.h
#ifndef PROTOCOL_SUPPORT_H
#define PROTOCOL_SUPPORT_H

void ParseEthernet(unsigned char *packet, int len);
int ParseIP(unsigned char *packet, int len);
int ParseTCP(unsigned char *packet, size_t len);

#endif /* PROTOCOL_SUPPORT_H */
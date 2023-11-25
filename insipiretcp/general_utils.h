// general_utils.h
#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H

void PrintInHex(const char *msg, const unsigned char *p, int len);
void GetTimeStamp(char *timestamp, size_t timestamp_size);
void PrintLayer (unsigned short protocol_id, int* current_position, unsigned short size_bytes, unsigned char *packet);
const char *ether_protocol_ntoa(unsigned short protocol_id);
#endif /* GENERAL_UTILS_H */
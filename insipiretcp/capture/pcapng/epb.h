#ifndef EPB_H
#define EPB_H
#include <stdint.h> // For fixed-width integer types

// Define a structure to represent an Enhanced Packet Block (EPB)
typedef struct __attribute__((packed)) EPB
{
    uint32_t blockType;                // Block Type = 0x00000006
    uint32_t blockTotalLength;         // Total Length of the Block
    uint32_t interfaceID;              // Interface ID
    uint32_t timestampUpper;           // Timestamp Upper
    uint32_t timestampLower;           // Timestamp Lower
    uint32_t capturedPacketLength;     // Captured Packet Length
    uint32_t originalPacketLength;     // Original Packet Length
    uint8_t *packetData;               // Packet Data
    uint32_t blockTotalLengthTrailing; // Total Length of the Block
} EPB;

// Function declarations
EPB *createEPB(uint32_t interfaceID, uint32_t capturedPacketLength, uint32_t originalPacketLength, uint8_t *packetData);
void freeEPB(EPB *epb);
uint64_t getCurrentTimestampMicroseconds();
#endif
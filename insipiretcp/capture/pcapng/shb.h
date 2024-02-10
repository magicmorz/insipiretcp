#ifndef SHB_H
#define SHB_H

#include <stdint.h> // For fixed-width integer types

// Define a structure to represent a Section Header Block (SHB)
typedef struct SHB
{
    uint32_t blockType;            // Block Type = 0x0A0D0D0A
    uint32_t blockTotalLength;     // Total Length of the Block
    uint32_t byteOrderMagic;       // Byte-Order Magic = 0x1A2B3C4D
    uint16_t majorVersion;         // Major Version = 0x0001
    uint16_t minorVersion;         // Minor Version = 0x0000
    uint64_t sectionLength;        // Section Length = 0xFFFFFFFFFFFFFFFF
    // Options (variable length)
    // Add more fields as needed
} SHB;

// Function to create a new SHB with options
SHB *createSHB(const char* hardwareName, const char* osName, const char* userAppName);

// Function to free memory allocated for SHB
void freeSHB(SHB *shb);

#endif /* SHB_H */

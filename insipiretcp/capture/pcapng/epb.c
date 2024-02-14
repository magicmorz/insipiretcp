#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h> // For fixed-width integer types
#include "epb.h"
#include <sys/time.h> // For gettimeofday function

// Function to create a new EPB
EPB *createEPB(uint32_t interfaceID, uint32_t capturedPacketLength,
               uint32_t originalPacketLength, uint8_t *packetData)
{
    EPB *newEPB = (EPB *)malloc(sizeof(EPB));
    if (newEPB == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // Get current timestamp in microseconds
    uint64_t timestampMicroseconds = getCurrentTimestampMicroseconds();

    // Split the timestamp into upper and lower parts (nanoseconds resolution)
    newEPB->timestampUpper = timestampMicroseconds >> 32;
    newEPB->timestampLower = timestampMicroseconds & 0xFFFFFFFF;

    newEPB->blockType = 0x00000006;                            // Block Type = 0x00000006 for EPB
    // Calculate the total length of the block, including padding
    uint32_t blockTotalLength = sizeof(EPB) - sizeof(uint32_t) + capturedPacketLength; // EPB structure size - blockTotalLength field size + capturedPacketLength
    // If the block total length is not a multiple of 4, add padding
    if (blockTotalLength % 4 != 0) {
        blockTotalLength += 4 - (blockTotalLength % 4);
    }
    newEPB->blockTotalLength = blockTotalLength;
    newEPB->interfaceID = interfaceID;
    newEPB->capturedPacketLength = capturedPacketLength;
    newEPB->originalPacketLength = originalPacketLength;
    newEPB->packetData = (uint8_t *)malloc(capturedPacketLength);
    if (newEPB->packetData == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    memcpy(newEPB->packetData, packetData, capturedPacketLength); // Copy packet data
    return newEPB;
}

// Function to free memory allocated for EPB
void freeEPB(EPB *epb)
{
    if (epb != NULL)
    {
        free(epb->packetData);
        free(epb);
    }
}

// Function to get the current timestamp in microseconds
uint64_t getCurrentTimestampMicroseconds()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

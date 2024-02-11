#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shb.h"

// Function to create a new SHB with options
SHB *createSHB(const char *hardwareName, const char *osName, const char *userAppName)
{
    hardwareName = NULL;
    hardwareName = "Intel(R) Core(TM) i5-6440HQ CPU @ 2.60GHz (with SSE4.2)";

    osName = NULL;
    osName = "64-bit Windows 10, build 14393";

    userAppName = NULL;
    userAppName = "Dumpcap (Wireshark) 2.6.1 (v2.6.1-0-g860a78b3)";
    // Calculate total length including options and padding
    uint32_t optionsLength = strlen(hardwareName) + strlen(osName) + strlen(userAppName) + 12; // 12 bytes for option headers
    uint32_t totalLength = sizeof(SHB) + optionsLength + 8;                                    // 8 bytes for trailing block

    SHB *newSHB = (SHB *)malloc(totalLength);
    if (newSHB == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // Populate SHB fields
    newSHB->blockType = 0x0A0D0D0A;             // Block Type = 0x0A0D0D0A for SHB
    newSHB->blockTotalLength = totalLength;     // Total Length of the Block including options and trailing block
    newSHB->byteOrderMagic = 0x1A2B3C4D;        // Byte-Order Magic = 0x1A2B3C4D
    newSHB->majorVersion = 0x0001;              // Major Version = 0x0001
    newSHB->minorVersion = 0x0000;              // Minor Version = 0x0000
    newSHB->sectionLength = 0xFFFFFFFFFFFFFFFF; // Section Length = 0xFFFFFFFFFFFFFFFF

    // Populate options
    uint8_t *optionsPtr = (uint8_t *)newSHB + sizeof(SHB);
    *optionsPtr++ = 0x02; // Option Code for hardware
    *optionsPtr++ = 0x00; // Option Length for hardware
    uint16_t hardwareNameLength = strlen(hardwareName);
    *((uint16_t *)optionsPtr) = hardwareNameLength;
    optionsPtr += 2;
    memcpy(optionsPtr, hardwareName, hardwareNameLength);
    optionsPtr += hardwareNameLength;
    *optionsPtr++ = 0x00; // Padding for hardware

    *optionsPtr++ = 0x03; // Option Code for OS
    *optionsPtr++ = 0x00; // Option Length for OS
    uint16_t osNameLength = strlen(osName);
    *((uint16_t *)optionsPtr) = osNameLength;
    optionsPtr += 2;
    memcpy(optionsPtr, osName, osNameLength);
    optionsPtr += osNameLength;
    *optionsPtr++ = 0x00; // Padding for OS
    *optionsPtr++ = 0x00; // Padding for OS
    *optionsPtr++ = 0x04; // Option Code for user application
    *optionsPtr++ = 0x00; // Option Length for user application
    uint16_t userAppNameLength = strlen(userAppName);
    *((uint16_t *)optionsPtr) = userAppNameLength;
    optionsPtr += 2;
    memcpy(optionsPtr, userAppName, userAppNameLength);
    optionsPtr += userAppNameLength;
    *optionsPtr++ = 0x00; // Padding for user application
    *optionsPtr++ = 0x00; // Padding for OS
    // End of options
    *((uint16_t *)optionsPtr) = 0x0000; // Option Code for end of options
    optionsPtr += 2;
    *optionsPtr++ = 0x00; // Padding for end of options

    // Trailing Block
    *((uint32_t *)optionsPtr) = totalLength; // Trailing Block Length
    optionsPtr += 4;
    *((uint32_t *)optionsPtr) = totalLength; // Trailing Block Length

    return newSHB;
}

// Function to free memory allocated for SHB
void freeSHB(SHB *shb)
{
    free(shb);
}

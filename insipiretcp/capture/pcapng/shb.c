#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shb.h"

// Function to create a new SHB with options
SHB *createSHB(const char *hardwareName, const char *osName, const char *userAppName)
{
    hardwareName = "Intel(R) Core(TM) i5-6440HQ CPU @ 2.60GHz (with SSE4.2)";
    osName = "64-bit Windows 10, build 14393";
    userAppName = "Dumpcap (Wireshark) 2.6.1 (v2.6.1-0-g860a78b3)";

    // Calculate option lengths
    uint32_t hardwareNameLength = strlen(hardwareName);
    uint32_t hardwareNamePaddingLength = 4 - ((2 + 2 + hardwareNameLength) % 4);

    uint32_t osNameLength = strlen(osName);
    uint32_t osNamePaddingLength = 4 - ((2 + 2 + osNameLength) % 4);

    uint32_t userAppNameLength = strlen(userAppName);
    uint32_t userAppNamePaddingLength = 4 - ((2 + 2 + userAppNameLength) % 4);

    // Calculate total length including options and padding
    uint32_t totalOptionsLength = hardwareNameLength + hardwareNamePaddingLength + osNameLength + osNamePaddingLength + userAppNameLength + userAppNamePaddingLength + 4 + 4 + 4;

    uint32_t totalLength = sizeof(SHB) + totalOptionsLength + 4 +4; // 4 bytes for options trailing block

    // Allocate memory for SHB
    SHB *newSHB = (SHB *)malloc(totalLength);
    if (newSHB == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // Populate SHB fields
    newSHB->blockType = 0x0A0D0D0A;
    newSHB->blockTotalLength = totalLength;
    newSHB->byteOrderMagic = 0x1A2B3C4D;
    newSHB->majorVersion = 0x0001;
    newSHB->minorVersion = 0x0000;
    newSHB->sectionLength = 0xFFFFFFFFFFFFFFFF;

    // Populate options
    uint8_t *optionsPtr = (uint8_t *)newSHB + sizeof(SHB);

    // Hardware Name
    *((uint32_t *)optionsPtr) = 2; // Option Code for hardware
    optionsPtr += 2;
    *((uint16_t *)optionsPtr) = hardwareNameLength;
    optionsPtr += 2;
    memcpy(optionsPtr, hardwareName, hardwareNameLength);
    optionsPtr += hardwareNameLength;
    memset(optionsPtr, 0x00, hardwareNamePaddingLength);
    optionsPtr += hardwareNamePaddingLength;

    // OS Name
    *((uint32_t *)optionsPtr) = 0x0003; // Option Code for OS
    optionsPtr += 2;
    *((uint16_t *)optionsPtr) = osNameLength;
    optionsPtr += 2;
    memcpy(optionsPtr, osName, osNameLength);
    optionsPtr += osNameLength;
    memset(optionsPtr, 0x00, osNamePaddingLength);
    optionsPtr += osNamePaddingLength;

    // User Application Name
    *((uint32_t *)optionsPtr) = 0x0004; // Option Code for user application
    optionsPtr += 2;
    *((uint16_t *)optionsPtr) = userAppNameLength;
    optionsPtr += 2;
    memcpy(optionsPtr, userAppName, userAppNameLength);
    optionsPtr += userAppNameLength;
    memset(optionsPtr, 0x00, userAppNamePaddingLength);
    optionsPtr += userAppNamePaddingLength;

    // End of options
    *((uint16_t *)optionsPtr) = 0x0000; // Option Code for end of options
    optionsPtr += 2;

    *((uint16_t *)optionsPtr) = 0x0000; // Padding

    // trailing block total length
    optionsPtr += 2;
    *((uint32_t *)optionsPtr) = newSHB->blockTotalLength;

    return newSHB;
}

// Function to free memory allocated for SHB
void freeSHB(SHB *shb)
{
    free(shb);
}

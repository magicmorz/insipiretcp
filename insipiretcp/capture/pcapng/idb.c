#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // For fixed-width integer types
#include <string.h>
#include "idb.h"

// Function to create a new IDB
IDB *createIDB(uint16_t linkType)
{

    const char *ifName = "\\Device\\NPF_{DFA364E5-4A94-4B58-BD9D-617A2C985989}";
    const char *ifDescription = "External 63.237.233.60 (aka 192.168.5.60)";
    const uint8_t ifTsresol = 6;
    const char *ifFilter = "ip host 96.93.107.34";
    const char *ifOs = "64-bit Windows Server 2012 R2, build 9600";

    // Calculate option lengths
    uint32_t ifNameLength = strlen(ifName);
    uint32_t ifNamePaddingLength = 4 - ((2 + 2 + ifNameLength) % 4);

    uint32_t ifDescriptionLength = strlen(ifDescription);
    uint32_t ifDescriptionPaddingLength = 4 - ((2 + 2 + ifDescriptionLength) % 4);

    uint32_t ifTsresolLength = sizeof(ifTsresol);
    uint32_t ifTsresolPaddingLength = 4 - ((2 + 2 + ifTsresolLength) % 4);

    uint32_t ifFilterLength = strlen(ifFilter);
    uint32_t ifFilterPaddingLength = 4 - ((2 + 2 + ifFilterLength) % 4);

    uint32_t ifOsLength = strlen(ifOs);
    uint32_t ifOsPaddingLength = 4 - ((2 + 2 + ifOsLength) % 4);

    // Calculate total length including options and padding
    uint32_t totalOptionsLength = ifNameLength + 4 + ifNamePaddingLength + ifDescriptionLength + 4 + ifDescriptionPaddingLength + ifTsresolLength + 4 + ifTsresolPaddingLength + ifFilterLength + 4 + ifFilterPaddingLength + ifOsLength + 4 + ifOsPaddingLength + 2 + 2;

    uint32_t blockTotalLength = sizeof(IDB) + totalOptionsLength + sizeof(uint32_t); // sizeof(uint32_t) for redundant block legth

    IDB *newIDB = (IDB *)malloc(blockTotalLength);
    if (newIDB == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    newIDB->blockType = 0x00000001; // Block Type = 0x00000001 for IDB
    newIDB->linkType = linkType;
    newIDB->reserved = 0x0000;
    newIDB->snapLength = 0x00040000; // maximum packet size 256kb

    newIDB->blockTotalLength = blockTotalLength;

    // Populate options
    uint8_t *optionsPtr = (uint8_t *)newIDB + sizeof(IDB);

    // interface Name
    *((uint32_t *)optionsPtr) = 2; // Option Code for interface name
    optionsPtr += 2;
    *((uint16_t *)optionsPtr) = ifNameLength;
    optionsPtr += 2;
    memcpy(optionsPtr, ifName, ifNameLength); // PROBLEMATIC LINE!!!!
    optionsPtr += ifNameLength;
    memset(optionsPtr, 0x00, ifNamePaddingLength);
    optionsPtr += ifNamePaddingLength;

    // interface description
    *((uint32_t *)optionsPtr) = 0x0003; // Option Code for interface description
    optionsPtr += 2;
    *((uint16_t *)optionsPtr) = ifDescriptionLength;
    optionsPtr += 2;
    memcpy(optionsPtr, ifDescription, ifDescriptionLength);
    optionsPtr += ifDescriptionLength;
    memset(optionsPtr, 0x00, ifDescriptionPaddingLength);
    optionsPtr += ifDescriptionPaddingLength;

    // time resolution
    *((uint32_t *)optionsPtr) = 0x0009; // Option Code for time resolution
    optionsPtr += 2;
    *((uint16_t *)optionsPtr) = sizeof(ifTsresol);
    optionsPtr += 2;
    memcpy(optionsPtr, &ifTsresol, sizeof(ifTsresol));
    optionsPtr += sizeof(ifTsresol);

    // interface filter
    *((uint32_t *)optionsPtr) = 0x000b; // Option Code for interface filter
    optionsPtr += 2;
    *((uint16_t *)optionsPtr) = ifFilterLength;
    optionsPtr += 2;
    memcpy(optionsPtr, ifFilter, ifFilterLength); // PROBLEMATIC LINE 2!!!
    optionsPtr += ifFilterLength;
    memset(optionsPtr, 0x00, ifFilterPaddingLength);
    optionsPtr += ifFilterPaddingLength;

    // interface os
    *((uint32_t *)optionsPtr) = 0x000c; // Option Code for interface os
    optionsPtr += 2;
    *((uint16_t *)optionsPtr) = ifOsLength;
    optionsPtr += 2;
    memcpy(optionsPtr, ifOs, ifOsLength);
    optionsPtr += ifOsLength;
    memset(optionsPtr, 0x00, ifOsPaddingLength);
    optionsPtr += ifOsPaddingLength;

    // End of options
    *((uint16_t *)optionsPtr) = 0x0000; // Option Code for end of options
    optionsPtr += 2;

    *((uint16_t *)optionsPtr) = 0x0000; // Padding

    optionsPtr += 2;
    memset(optionsPtr, blockTotalLength, sizeof(blockTotalLength));

    return newIDB;
}

// Function to free memory allocated for IDB
void freeIDB(IDB *idb)
{
    free(idb);
}

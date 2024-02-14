#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // For fixed-width integer types
#include "idb.h"

// Function to create a new IDB
IDB *createIDB(uint16_t linkType)
{
    IDB *newIDB = (IDB *)malloc(sizeof(IDB));
    if (newIDB == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    newIDB->blockType = 0x00000001;                            // Block Type = 0x00000001 for IDB
    // Calculate the total length of the block, including padding
    uint32_t blockTotalLength = sizeof(IDB) + 2; // IDB structure size + linkType field size
    // If the block total length is not a multiple of 4, add padding
    if (blockTotalLength % 4 != 0) {
        blockTotalLength += 4 - (blockTotalLength % 4);
    }
    newIDB->blockTotalLength = blockTotalLength;
    newIDB->linkType = linkType;
    return newIDB;
}

// Function to free memory allocated for IDB
void freeIDB(IDB *idb)
{
    free(idb);
}

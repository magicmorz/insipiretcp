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
    newIDB->blockTotalLength = sizeof(IDB);                    // Total Length of the Block including the linkType field
    newIDB->linkType = linkType;
    return newIDB;
}

// Function to free memory allocated for IDB
void freeIDB(IDB *idb)
{
    free(idb);
}

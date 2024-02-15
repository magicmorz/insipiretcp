#ifndef IDB_H
#define IDB_H

#include <stdint.h> // For fixed-width integer types

// Define a structure to represent an Interface Description Block (IDB)
typedef struct IDB
{
    uint32_t blockType;        // Block Type = 0x00000001
    uint32_t blockTotalLength; // Total Length of the Block
    uint16_t linkType;         // Link Type
    uint16_t reserved;         // reserved
    uint32_t snapLength;       // Total Length of the Block
} IDB;

// Function to create a new IDB
IDB *createIDB(uint16_t linkType);

// Function to free memory allocated for IDB
void freeIDB(IDB *idb);

#endif /* IDB_H */

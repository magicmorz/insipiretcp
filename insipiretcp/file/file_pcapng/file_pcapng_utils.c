#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../capture/pcapng/pcapng.h"

// Function to save PCAPNG structure to a file
int savePCAPNGToFile(PCAPNG *pcapng, const char *filename) {
    FILE *file = fopen(filename, "wb");
    // If the file can be opened successfully, its contents will be truncated, 
    // meaning all existing data will be deleted
    if (file == NULL) {
        perror("Failed to open file for writing");
        return -1;
    }

    // Write SHB to file
    if (fwrite(pcapng->shb, 1, sizeof(SHB), file) != sizeof(SHB)) {
        perror("Failed to write SHB to file");
        fclose(file);
        return -1;
    }

    // Write IDBs to file
    IDB_Node *idbNode = pcapng->idbList;
    while (idbNode != NULL) {
        if (fwrite(idbNode->idb, 1, sizeof(IDB), file) != sizeof(IDB)) {
            perror("Failed to write IDB to file");
            fclose(file);
            return -1;
        }
        idbNode = idbNode->next;
    }

    // Write EPBs to file
    EPB_Node *epbNode = pcapng->epbList;
    while (epbNode != NULL) {
        // Write EPB excluding the packetData field
        if (fwrite(epbNode->epb, 1, sizeof(EPB) - sizeof(uint8_t*), file) != sizeof(EPB) - sizeof(uint8_t*)) {
            perror("Failed to write EPB to file");
            fclose(file);
            return -1;
        }
        // Write packetData separately
        if (fwrite(epbNode->epb->packetData, 1, epbNode->epb->capturedPacketLength, file) != epbNode->epb->capturedPacketLength) {
            perror("Failed to write packetData to file");
            fclose(file);
            return -1;
        }
        epbNode = epbNode->next;
    }

    fclose(file);
    return 0;
}

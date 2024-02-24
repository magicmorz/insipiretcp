#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../capture/pcapng/pcapng.h"

// Function to save PCAPNG structure to a file
int savePCAPNGToFile(PCAPNG *pcapng, const char *filename)
{
    FILE *file = fopen(filename, "wb");
    // If the file can be opened successfully, its contents will be truncated,
    // meaning all existing data will be deleted
    if (file == NULL)
    {
        perror("Failed to open file for writing");
        return -1;
    }

    // Write SHB to file
    size_t elements_written = fwrite(pcapng->shb, sizeof(char), (pcapng->shb->blockTotalLength), file);
    if (elements_written != (pcapng->shb->blockTotalLength))
    {
        perror("Failed to write SHB to file");
        fclose(file);
        return -1;
    }

    // Write IDBs to file
    IDB_Node *idbNode = pcapng->idbList;
    while (idbNode != NULL)
    {
        if (fwrite(idbNode->idb, sizeof(char), idbNode->idb->blockTotalLength, file) != idbNode->idb->blockTotalLength)
        {
            perror("Failed to write IDB to file");
            fclose(file);
            return -1;
        }
        idbNode = idbNode->next;
    }

    // Write EPBs to file
    EPB_Node *epbNode = pcapng->epbList;
    while (epbNode != NULL)
    {
        size_t bufferSize = (sizeof(EPB) - sizeof(uint8_t *) - sizeof(uint32_t)) * sizeof(char);
        char *buffer = (char *)malloc(bufferSize);
        memcpy(buffer, epbNode->epb, bufferSize);
        // Write EPB excluding the packetData field
        if (fwrite(buffer, sizeof(char), bufferSize, file) != bufferSize)
        {
            perror("Failed to write EPB to file");
            fclose(file);
            return -1;
        }
        free(buffer);

        EPB *currentEPB = epbNode->epb; 

        bufferSize = ((currentEPB->capturedPacketLength) * sizeof(char));
        size_t paddingSize = (4 - (bufferSize%4))%4;
        bufferSize += paddingSize;

        buffer = (char *)calloc(sizeof(char),bufferSize);
        
        memcpy(buffer, currentEPB->packetData, bufferSize);
        // Write packetData
        if (fwrite(buffer, sizeof(char), bufferSize, file) != bufferSize)
        {
            perror("Failed to write EPB to file");
            fclose(file);
            return -1;
        }
        free(buffer);

        bufferSize = (sizeof(epbNode->epb->blockTotalLengthTrailing) * sizeof(char));
        buffer = (char *)malloc(bufferSize);
        memcpy(buffer, &(epbNode->epb->blockTotalLengthTrailing), bufferSize);
        // Write trailing block length
        if (fwrite(buffer, sizeof(char), bufferSize, file) != bufferSize)
        {
            perror("Failed to write EPB to file");
            fclose(file);
            return -1;
        }
        free(buffer);
        epbNode = epbNode->next;
    }

    fclose(file);
    return 0;
}
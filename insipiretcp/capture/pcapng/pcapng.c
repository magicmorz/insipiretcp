#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pcapng.h"
#include <sys/utsname.h> // For uname system call (get the system specs like CPU and OS)

// Function to create a new PCAPNG structure
PCAPNG *createPCAPNG()
{
    PCAPNG *pcapng = (PCAPNG *)malloc(sizeof(PCAPNG));
    if (pcapng == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    // Variables to store system information
    char *hardware = (char *)calloc(256, sizeof(char)); // Assuming maximum length of hardware information
    if (hardware == NULL)
    {
        printf("Memory allocation failed\n");
        return NULL; // Exit with an error code
    }

    char *os = (char *)calloc(256, sizeof(char)); // Assuming maximum length of operating system information
    if (os == NULL)
    {
        printf("Memory allocation failed\n");
        return NULL; // Exit with an error code
    }
    char userappl[] = "inspireTCP 0.0.1";

    getSystemInformation(hardware, os);
    // Get system information
    pcapng->shb = createSHB(hardware, os, userappl); // Create Section Header Block
    pcapng->idbList = NULL;                          // Initialize IDB linked list to empty
    pcapng->epbList = NULL;                          // Initialize EPB linked list to empty
    return pcapng;
}

// Function to free memory allocated for PCAPNG structure
void freePCAPNG(PCAPNG *pcapng)
{
    if (pcapng != NULL)
    {
        freeSHB(pcapng->shb);             // Free Section Header Block
        freeIDBNodeList(pcapng->idbList); // Free IDB linked list
        freeEPBNodeList(pcapng->epbList); // Free EPB linked list
        free(pcapng);
    }
}

// Function to create a new IDB node
IDB_Node *createIDBNode(IDB *idb)
{
    IDB_Node *newNode = (IDB_Node *)malloc(sizeof(IDB_Node));
    if (newNode == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    newNode->idb = idb;
    newNode->next = NULL;
    return newNode;
}

// Function to add a new IDB node to the linked list
void addIDBNode(PCAPNG *pcapng, IDB *idb)
{
    IDB_Node *newNode = createIDBNode(idb);
    if (pcapng->idbList == NULL)
    {
        pcapng->idbList = newNode;
    }
    else
    {
        IDB_Node *current = pcapng->idbList;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = newNode;
    }
}

// Function to free memory allocated for the IDB node linked list
void freeIDBNodeList(IDB_Node *idbList)
{
    IDB_Node *current = idbList;
    while (current != NULL)
    {
        IDB_Node *temp = current;
        current = current->next;
        freeIDB(temp->idb);
        free(temp);
    }
}

// Function to create a new EPB node
EPB_Node *createEPBNode(EPB *epb)
{
    EPB_Node *newNode = (EPB_Node *)malloc(sizeof(EPB_Node));
    if (newNode == NULL)
    {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    newNode->epb = epb;
    newNode->next = NULL;
    return newNode;
}

// Function to add a new EPB node to the linked list
void addEPBNode(PCAPNG *pcapng, EPB *epb)
{
    EPB_Node *newNode = createEPBNode(epb);
    if (pcapng->epbList == NULL)
    {
        pcapng->epbList = newNode;
    }
    else
    {
        EPB_Node *current = pcapng->epbList;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = newNode;
    }
}

// Function to free memory allocated for the EPB node linked list
void freeEPBNodeList(EPB_Node *epbList)
{
    EPB_Node *current = epbList;
    while (current != NULL)
    {
        EPB_Node *temp = current;
        current = current->next;
        free(temp->epb->packetData);
        free(temp->epb);
        free(temp);
    }
}

// Function to retrieve system information using the uname system call
void getSystemInformation(char *hardware, char *os)
{
    struct utsname sys_info;

    // Get system information using uname
    if (uname(&sys_info) == -1)
    {
        perror("uname");
        exit(EXIT_FAILURE);
    }

    strcpy(hardware, sys_info.machine);
    snprintf(os, sizeof(sys_info.sysname) + sizeof(sys_info.release) + 2, "%s %s", sys_info.sysname, sys_info.release);
}

// Function to print a Section Header Block (SHB) including options
void printSHB(const SHB *shb) {
    printf("Section Header Block (SHB):\n");
    printf("Block Type: 0x%08X (Size: %zu bytes)\n", shb->blockType, sizeof(shb->blockType));
    printf("Block Total Length: %u (Size: %zu bytes)\n", shb->blockTotalLength, sizeof(shb->blockTotalLength));
    // Print more SHB fields as needed

    // Print options
    const uint8_t *optionsPtr = (const uint8_t *)shb + sizeof(SHB);
    while (*optionsPtr != 0x00) {
        printf("Option Code: 0x%02X (Size: %zu bytes)\n", *optionsPtr++, sizeof(uint8_t));
        printf("Option Length: %u (Size: %zu bytes)\n", *optionsPtr++, sizeof(uint8_t));
        uint16_t optionLength = *((uint16_t *)optionsPtr);
        optionsPtr += 2;
        printf("Option Value: ");
        for (uint16_t i = 0; i < optionLength; i++) {
            printf("%02X ", *optionsPtr++);
        }
        printf("(Size: %u bytes)\n", optionLength);
        // Add padding bytes if necessary
        size_t paddingBytes = (4 - (optionLength % 4)) % 4;
        optionsPtr += paddingBytes;
    }
    printf("\n");
}

// Function to print an Interface Description Block (IDB) including options
void printIDB(const IDB *idb) {
    printf("Interface Description Block (IDB):\n");
    printf("Block Type: 0x%08X (Size: %zu bytes)\n", idb->blockType, sizeof(idb->blockType));
    printf("Block Total Length: %u (Size: %zu bytes)\n", idb->blockTotalLength, sizeof(idb->blockTotalLength));
    printf("Link Type ID: %u (Size: %zu bytes)\n", idb->linkType, sizeof(idb->linkType));
    // Print more IDB fields as needed

    // Print options
    const uint8_t *optionsPtr = (const uint8_t *)idb + sizeof(IDB);
    while (*optionsPtr != 0x00) {
        printf("Option Code: 0x%02X (Size: %zu bytes)\n", *optionsPtr++, sizeof(uint8_t));
        printf("Option Length: %u (Size: %zu bytes)\n", *optionsPtr++, sizeof(uint8_t));
        uint16_t optionLength = *((uint16_t *)optionsPtr);
        optionsPtr += 2;
        printf("Option Value: ");
        for (uint16_t i = 0; i < optionLength; i++) {
            printf("%02X ", *optionsPtr++);
        }
        printf("(Size: %u bytes)\n", optionLength);
        // Add padding bytes if necessary
        size_t paddingBytes = (4 - (optionLength % 4)) % 4;
        optionsPtr += paddingBytes;
    }
    printf("\n");
}

// Function to print an Enhanced Packet Block (EPB) including options
void printEPB(const EPB *epb) {
    printf("Enhanced Packet Block (EPB):\n");
    printf("Block Type: 0x%08X (Size: %zu bytes)\n", epb->blockType, sizeof(epb->blockType));
    printf("Block Total Length: %u (Size: %zu bytes)\n", epb->blockTotalLength, sizeof(epb->blockTotalLength));
    printf("Interface ID: %u (Size: %zu bytes)\n", epb->interfaceID, sizeof(epb->interfaceID));
    printf("Timestamp Upper: %u (Size: %zu bytes)\n", epb->timestampUpper, sizeof(epb->timestampUpper));
    printf("Timestamp Lower: %u (Size: %zu bytes)\n", epb->timestampLower, sizeof(epb->timestampLower));
    printf("Captured Packet Length: %u (Size: %zu bytes)\n", epb->capturedPacketLength, sizeof(epb->capturedPacketLength));
    printf("Original Packet Length: %u (Size: %zu bytes)\n", epb->originalPacketLength, sizeof(epb->originalPacketLength));
    // Print more EPB fields as needed

    // Print options
    const uint8_t *optionsPtr = (const uint8_t *)epb + sizeof(EPB);
    while (*optionsPtr != 0x00) {
        printf("Option Code: 0x%02X (Size: %zu bytes)\n", *optionsPtr++, sizeof(uint8_t));
        printf("Option Length: %u (Size: %zu bytes)\n", *optionsPtr++, sizeof(uint8_t));
        uint16_t optionLength = *((uint16_t *)optionsPtr);
        optionsPtr += 2;
        printf("Option Value: ");
        for (uint16_t i = 0; i < optionLength; i++) {
            printf("%02X ", *optionsPtr++);
        }
        printf("(Size: %u bytes)\n", optionLength);
        // Add padding bytes if necessary
        size_t paddingBytes = (4 - (optionLength % 4)) % 4;
        optionsPtr += paddingBytes;
    }
    printf("\n");
}

// Function to print the entire PCAPNG structure including options
void printPCAPNG(const PCAPNG *pcapng) {
    printf("Printing PCAPNG Structure:\n\n");
    printSHB(pcapng->shb);

    // Print IDB list
    IDB_Node *idbNode = pcapng->idbList;
    while (idbNode != NULL) {
        printIDB(idbNode->idb);
        idbNode = idbNode->next;
    }

    // Print EPB list
    EPB_Node *epbNode = pcapng->epbList;
    while (epbNode != NULL) {
        printEPB(epbNode->epb);
        epbNode = epbNode->next;
    }
}

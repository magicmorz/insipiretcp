#ifndef PCAPNG_H
#define PCAPNG_H

#include <stdint.h>
#include "shb.h"
#include "idb.h"
#include "epb.h"

typedef struct IDB_Node
{
    IDB *idb;              // Interface Description Block
    struct IDB_Node *next; // Pointer to the next IDB node
} IDB_Node;

typedef struct EPB_Node
{
    EPB *epb;              // Enhanced Packet Block
    struct EPB_Node *next; // Pointer to the next EPB node
} EPB_Node;

// structure to represent the PCAPNG file, containing SHB, IDB linked list, and EPB linked list
typedef struct PCAPNG
{
    SHB *shb;          // Section Header Block
    IDB_Node *idbList; // Interface Description Block linked list
    EPB_Node *epbList; // Enhanced Packet Block linked list
} PCAPNG;

// Function prototypes
PCAPNG *createPCAPNG();
void freePCAPNG(PCAPNG *pcapng);
size_t calculatePCAPNGSize(const PCAPNG *pcapng);
IDB_Node *createIDBNode(IDB *idb);
void addIDBNode(PCAPNG *pcapng, IDB *idb);
void freeIDBNodeList(IDB_Node *idbList);
EPB_Node *createEPBNode(EPB *epb);
void addEPBNode(PCAPNG *pcapng, EPB *epb);
void freeEPBNodeList(EPB_Node *epbList);
void getSystemInformation(char *hardware, char *os);
void printPCAPNG(const PCAPNG *pcapng);
size_t calculatePaddingFor32bit(size_t packet_length);
#endif /* PCAPNG_H */

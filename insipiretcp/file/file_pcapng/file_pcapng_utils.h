#ifndef FILE_PCAPNG_UTILS_H
#define FILE_PCAPNG_UTILS_H

#include <stdio.h>
#include "../../capture/pcapng/pcapng.h"

// Function declarations
int savePCAPNGToFile(PCAPNG *pcapng, const char *filename);

#endif

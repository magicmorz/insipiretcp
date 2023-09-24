#include <stdio.h>

void PrintInHex(char *msg, unsigned char *p, int len)
{
    printf(msg);
    while (len--)
    {
        printf("%.2X ", *p);
        p++;
    }
    
}
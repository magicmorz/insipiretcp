#include <stdio.h>

void PrintInHex(const char *msg, const unsigned char *p, int len)
{
    printf("%s", msg);
    while (len--)
    {
        printf("%.2X ", *p);
        p++;
    }
    
}
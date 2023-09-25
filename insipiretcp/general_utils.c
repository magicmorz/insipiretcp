#include <stdio.h>
#include <sys/time.h>
#include <time.h>

void PrintInHex(const char *msg, const unsigned char *p, int len)
{
    printf("%s", msg);
    while (len--)
    {
        printf("%.2X ", *p);
        p++;
    }
    
}

void GetTimeStamp(char *timestamp, size_t timestamp_size) {
    if (timestamp_size < 30) {
        // Ensure there's enough space for the timestamp
        fprintf(stderr, "Timestamp buffer too small\n");
        return;
    }

    struct timeval current_time;
    gettimeofday(&current_time, NULL);

    // Use strftime and localtime correctly
    struct tm *local_time = localtime(&current_time.tv_sec);
    if (local_time == NULL) {
        perror("localtime");
        return;
    }

    // Format the timestamp as "YYYY-MM-DD HH:MM:SS.ssssss"
    strftime(timestamp, timestamp_size, "%Y-%m-%d %H:%M:%S", local_time);

    // Append the microseconds part
    snprintf(timestamp + 19, timestamp_size - 19, ".%06ld", current_time.tv_usec);
}
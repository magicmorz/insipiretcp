#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

typedef ssize_t (*original_send_func)(int sockfd, const void *buf, size_t len, int flags);

original_send_func original_send;

int is_duplicated = 0; // Flag to track if message is duplicated

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    original_send_func original_send_func_ptr;
    original_send_func_ptr = dlsym(RTLD_NEXT, "send");

    ssize_t result = original_send_func_ptr(sockfd, buf, len, flags);

    if (!is_duplicated)
    {
        // Duplicate the message to homeserver
        int homeserver_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in homeserver_addr;
        homeserver_addr.sin_family = AF_INET;
        homeserver_addr.sin_port = htons(8200);
        homeserver_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        connect(homeserver_sock, (struct sockaddr *)&homeserver_addr, sizeof(homeserver_addr));
        send(homeserver_sock, buf, len, flags);
        close(homeserver_sock);

        is_duplicated = 1; // Set the flag to indicate the message is duplicated
    }

    return result;
}

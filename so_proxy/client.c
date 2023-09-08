#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int main()
{
    int clientSocket;
    struct sockaddr_in serverAddr;

    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    // Set up server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        perror("Connection error");
        exit(EXIT_FAILURE);
    }

    // Communication with the server
    char message[] = "Hello, server!";
    char response[1024];
    ssize_t bytesRead;
    // Send data to the server
    send(clientSocket, message, strlen(message), 0);

    // Receive response from the server
    bytesRead = recv(clientSocket, response, sizeof(response), 0);
    if (bytesRead > 0)
    {
        response[bytesRead] = '\0';
        printf("Server response: %s\n", response);
    }

    // Close the client socket
    close(clientSocket);

    return 0;
}

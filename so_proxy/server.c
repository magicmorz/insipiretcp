#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>

int main()
{
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    // Set up server address structure
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(12345);

    // Bind the socket
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        perror("Bind error");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(serverSocket, 5) == -1)
    {
        perror("Listen error");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port 12345...\n");

    while (1)
    {
        // Accept incoming connection
        clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addrLen);
        if (clientSocket == -1)
        {
            perror("Accept error");
            continue; // Continue listening for more connections
        }

        // Fork a new process to handle the client
        if (fork() == 0)
        {
            // Close the server socket in the child process
            close(serverSocket);

            printf("Connected to client: %s\n", inet_ntoa(clientAddr.sin_addr));

            // Communication with the client
            char buffer[1024];
            ssize_t bytesRead;

            while (1)
            {
                // Receive data from the client
                bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
                if (bytesRead <= 0)
                {
                    perror("Receive error or client disconnected");
                    break;
                }

                // Process received data
                printf("Received: %s", buffer);

                // Send a response back to the client
                send(clientSocket, "Message received.", 17, 0);
            }

            // Close the client socket and exit the child process
            close(clientSocket);
            exit(0);
        }

        // Close the client socket in the parent process
        close(clientSocket);

        // Clean up any finished child processes
        while (waitpid(-1, NULL, WNOHANG) > 0)
            ;
    }

    // Close the server socket (never reached in this example)
    close(serverSocket);

    return 0;
}

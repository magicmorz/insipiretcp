// main.c
#include "common.h"
#include "sniffer.h"

int main(int argc, char *argv[]) {
    // -----------start of sudo debug enabling
     /*
    The sole purprose of this code is to enable debugging with sudo in vscode.
    In order to make it work, make the following steps:
    1. add to launch.json:
        {
        "miDebuggerPath": "${workspaceFolder}/gdb_root.sh"
        }
    2. create file gdb_root.sh:
        #!/bin/bash
        SELF_PATH=$(realpath -s "$0")

        if [[ "$SUDO_ASKPASS" = "$SELF_PATH" ]]; then
        zenity --password --title="$1"
        else
        exec env SUDO_ASKPASS="$SELF_PATH" sudo -A /usr/bin/gdb $@
        fi
    3.  chmod +x gdb_root.sh
    4.  add the following code block to main with the needed #include-s
    */
    char *sudo_uid = getenv("SUDO_UID");
    if (sudo_uid)
        setresuid(0, 0, atoi(sudo_uid));

    printf("uid = %d\n", getuid());
    // -----------end of sudo debug enabling 

    char *interface_name;
    int num_packets;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <num_packets>\n", argv[0]);
        return EXIT_FAILURE;
    }

    interface_name = argv[1];
    num_packets = atoi(argv[2]);

    // Create a raw socket
    int sockfd = CreateRawSocket(ETH_P_ALL);

    // Bind the raw socket to the specified network interface
    BindRawSocketToInterface(sockfd, interface_name);

    printf("Sniffing %d packets on interface %s...\n", num_packets, interface_name);

    for (int i = 0; i < num_packets; i++) {
        unsigned char packet[2048]; // Adjust the size as needed
        int packet_length;

        // Receive a packet
        packet_length = recvfrom(sockfd, packet, sizeof(packet), 0, NULL, NULL);
        if (packet_length == -1) {
            perror("Packet receive error");
            close(sockfd);
            return EXIT_FAILURE;
        }

        printf("Packet %d:\n", i + 1);

        // Print the packet in hexadecimal form
        PrintPacketInHex(packet, packet_length);
    }

    // Close the socket
    close(sockfd);

    return EXIT_SUCCESS;
}

CC = gcc
CFLAGS = -Wall -Wextra -g

all: client server homeserver clienthack.so

client: client.c
	$(CC) $(CFLAGS) -o client client.c

server: server.c
	$(CC) $(CFLAGS) -o server server.c

homeserver: homeserver.c
	$(CC) $(CFLAGS) -o homeserver homeserver.c

clienthack.so: clienthack.c
	$(CC) $(CFLAGS) -shared -o clienthack.so clienthack.c -ldl -fPIC

clean:
	rm -f client server homeserver clienthack.so

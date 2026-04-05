# SimpleMail - Makefile

CC = gcc
CFLAGS = -Wall -Wextra -g

all: smserver smclient

smserver: smserver.c
	$(CC) $(CFLAGS) -o smserver smserver.c

smclient: smclient.c
	$(CC) $(CFLAGS) -o smclient smclient.c

clean:
	rm -rf smserver smclient mailbox/

.PHONY: all clean

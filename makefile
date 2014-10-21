CC = gcc -Wall
PCAPLIB	= -lpcap

all: https

https: https.c
	$(CC)  -c https.c -o https.o
	$(CC)  https.o -o https $(PCAPLIB)
clean:	
	rm -f *.o https
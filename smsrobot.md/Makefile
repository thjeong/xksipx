# This makefile compiles the source code for the "SMS robot XKSTYLE"

CC = /usr/local/bin/gcc

CFLAGS =

client: client.h digcalc.o md5c.o base64.o client.o
	$(CC) $(CFLAGS) -o client digcalc.o md5c.o base64.o client.o

digcalc.o: global.h md5.h
	$(CC) -c -O digcalc.c

md5c.o: global.h md5.h
	$(CC) -c -O md5c.c

client.o: client.h digcalc.h
	$(CC) -c -O client.c

base64.o:
	$(CC) -c -O base64.c
clean:
	rm -f *.o client

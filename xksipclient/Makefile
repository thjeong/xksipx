# This makefile compiles the source code for the "SMS robot XKSTYLE"

CC = /usr/bin/gcc

CFLAGS = -lpthread

client: xksip.h parsing.o digcalc.o md5c.o base64.o genmsg.o sendudp.o xksip.o
	$(CC) $(CFLAGS) -o xksip parsing.c digcalc.o md5c.o base64.o genmsg.o sendudp.o xksip.o

parsing.o: global.h sip_attrs.h xksip.h
	$(CC) -c -O parsing.c

digcalc.o: global.h md5.h
	$(CC) -c -O digcalc.c

md5c.o: global.h md5.h
	$(CC) -c -O md5c.c

genmsg.o: global.h md5.h digcalc.h
	$(CC) -c -O genmsg.c

sendudp.o:
	$(CC) -c -O sendudp.c

xksip.o: xksip.h digcalc.h
	$(CC) -c -O xksip.c

base64.o:
	$(CC) -c -O base64.c
clean:
	rm -f *.o xksip

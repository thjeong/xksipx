#
# Makefile Configuration
# Date : Feb, 25 2008
# Make : xkstyle
#

CC = gcc


CFLAGS = -m64 -Dlinux -g
CPPFLAGS = -I /u01/app/oracle/product/10.1.0/db_1/rdbms/public
CLIBS = -L /u01/app/oracle/product/10.1.0/db_1/lib -L /u01/app/oracle/product/10.1.0/db_1/rdbms/lib -lclntsh

#CFLAGS = -m32 -Dlinux 
#CPPFLAGS = -I /u01/app/oracle/product/10.2.0/db_2/rdbms/public
#CLIBS = -L /u01/app/oracle/product/10.2.0/db_2/lib32 -L /u01/app/oracle/product/10.2.0/db_2/rdbms/lib32 -lclntsh

SRCS = parsing.c proc.c util.c engine.c
OBJS = $(SRCS:.c=.o)
TARGET = wyzldr

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(CFLAGS) $(OBJS) $(CLIBS)

clean:
	rm -f *.o wyzldr


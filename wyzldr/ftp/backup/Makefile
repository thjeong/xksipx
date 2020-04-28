#
# Makefile Configuration
# Date : Apr, 3 2007
# Make : Steven, Oh (MLT, CO., Ltd. Seoul, KOREA)
#

CC = gcc


CFLAGS = -Dlinux
CPPFLAGS = -I /u01/app/oracle/product/10.1.0/db_1/rdbms/public
CLIBS = -L /u01/app/oracle/product/10.1.0/db_1/lib -L /u01/app/oracle/product/10.1.0/db_1/rdbms/lib -lclntsh

#CFLAGS = -m32 -Dlinux
#CPPFLAGS = -I /u01/app/oracle/product/10.1.0/db_1/rdbms/public
#CLIBS = -L /u01/app/oracle/product/10.1.0/db_1/lib32 -L /u01/app/oracle/product/10.1.0/db_1/rdbms/lib32 -lclntsh

SRCS = xkftp.c proc.c
OBJS = $(SRCS:.c=.o)
TARGET = xkftp 

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(CFLAGS) $(OBJS) $(CLIBS)

clean:
	rm -f *.o xkftp


# Copyright (C) Information Equipment co.,LTD
# All rights reserved.
# Code by JaeHyuk Cho <mailto:minzkn@infoeq.com>
# CVSTAG="$Header$"

# bash$ make TARGET_ARCH=i386 all
# bash$ make TARGET_ARCH=mips all
# bash$ make TARGET_ARCH=ppc all
# bash$ make TARGET_ARCH=arm all

TARGET_ARCH                  :=i386
# TARGET_ARCH                  :=mips
# TARGET_ARCH                  :=ppc
# TARGET_ARCH                  :=arm

ifeq ($(findstring mips,$(TARGET_ARCH)),mips)
 CROSS_COMPILE               :=/opt/kenati/bin/lx4189-uclibc-#
else
 ifeq ($(findstring ppc,$(TARGET_ARCH)),ppc)
  CROSS_COMPILE              :=/opt/hardhat/devkit/ppc/405/bin/ppc_405-#
 else
  ifeq ($(findstring arm,$(TARGET_ARCH)),arm)
   CROSS_COMPILE             :=/usr/local/arm-linux/bin/arm-linux-#
  else
   ifeq ($(findstring i386,$(TARGET_ARCH)),i386)
    CROSS_COMPILE            :=#
   else
    CROSS_COMPILE            :=#
   endif
  endif
 endif
endif

CC                           := $(CROSS_COMPILE)gcc
RM                           := rm -f

CFLAGS                       := -O2 -Wall -Werror -fomit-frame-pointer -pipe -I.
CFLAGS                       += -g 
#CFLAGS                       += -v
#CFLAGS                       += -ansi# -std=c89
#CFLAGS                       += -traditional -E
#CFLAGS                       += -std=c99
CFLAGS                       += -D_REENTRANT
LDFLAGS                      := -s

TARGET                       := mzbase64

OBJECT_mzsignal              := base64.o

OBJECTS                      := $(OBJECT_mzsignal)

.PHONY: all clean

all: $(TARGET)
clean: ; $(RM) *.o $(TARGET)

$(OBJECTS): Makefile

$(TARGET): $(OBJECT_mzsignal) ; $(CC) $(LDFLAGS) -o $(@) $(^)

%.o: %.c ; $(CC) $(CFLAGS) -c -o $(@) $(<)

# End of Makefile

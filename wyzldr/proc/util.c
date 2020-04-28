/*******************************************************************************
 *  Copyrights(c) 2007~ Modern Limes Technology(MLT) Co., Ltd. Seoul Korea
 *  
 * All rights are reserved. This is unpublished proprietary source code of MLT.
 * The copyright notice does not evidence any actual publication of such source
 * code.
 * 
 *      Subject : SIP Packet's Parser Utility module
 *      Authors : Steven, Oh. MLT
 *      Date : Apr 3, 2007 
 * 
 *      Overview
 * 
 * $Log$
 * 
 ******************************************************************************/

/*******************************************************************************
 * IMPORTED SYSTEM HEADER FILES
 ******************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

/*******************************************************************************
 * OTHER IMPORTED HEADER FILES
 ******************************************************************************/
#include "types.h"

/*******************************************************************************
 * PRIVATE DEFINITIONS
 ******************************************************************************/

/*******************************************************************************
 * PRIVATE TYPE DEFINITIONS
 ******************************************************************************/

/*******************************************************************************
 * PRIVATE FUNCTION PROTOTYPES
 ******************************************************************************/

/*******************************************************************************
 * INTERFACE VARIABLES
 ******************************************************************************/

/*******************************************************************************
 * PUBLIC VARIABLES
 ******************************************************************************/
clock_t end;

/*******************************************************************************
 * PRIVATE VARIABLES
 ******************************************************************************/

/*******************************************************************************
 * IMPLEMENTATION OF INTERFACE FUNCTIONS
 ******************************************************************************/

/*******************************************************************************
 * IMPLEMENTATION OF PUBLIC FUNCTIONS
 ******************************************************************************/

#ifndef linux

#define ntohl(x) __bswap_32 (x)
#define ntohs(x) __bswap_16 (x)
#define htonl(x) __bswap_32 (x)
#define htons(x) __bswap_16 (x)

static __inline unsigned short int
__bswap_16 (unsigned short int __bsx)
{
          return ((((__bsx) >> 8) & 0xff) | (((__bsx) & 0xff) << 8));
}

static __inline unsigned int
__bswap_32 (unsigned int __bsx)
{
          return ((((__bsx) & 0xff000000) >> 24) | (((__bsx) & 0x00ff0000) >>  8) |
                                (((__bsx) & 0x0000ff00) <<  8) | (((__bsx) & 0x000000ff) << 24));
}

char *inet_ntoa_b(struct in_addr ipaddr)
{
    static char result[30];
    int i, len = 0;
    unsigned char *p;
        unsigned int ip = ipaddr.s_addr;

    memset(result, 0, 30);
    for (i = 0, p = (char*)&ip; i < 4; i++, p++) {
        len += sprintf(result + len, "%d", *p);
        if (i != 3)
            len += sprintf(result + len, ".");
    }
    return result;
}
#endif
#if 1   // HJCHOI 2007.11.12
char *inet_ntoa_b(struct in_addr ipaddr)
{
    static char result[30];
    int i, len = 0;
    unsigned char *p;
        unsigned int ip = ipaddr.s_addr;

    memset(result, 0, 30);
    for (i = 0, p = (char*)&ip; i < 4; i++, p++) {
        len += sprintf(result + len, "%d", *p);
        if (i != 3)
            len += sprintf(result + len, ".");
    }
    return result;
}
#endif


/*******************************************************************************
 * NAME : parser's util function
 * ARGUMENT : clock_t, clock_t
 * RETURNS/SIDE-EFFECTS : char*
 ******************************************************************************/
long
display_interval(clock_t start, clock_t end)
{
   long time_elapsed;
   clock_t terms;

   terms = end - start;

   time_elapsed = ((terms / CLOCKS_PER_SEC)  * 1000) + ((terms % CLOCKS_PER_SEC) * 1000 / CLOCKS_PER_SEC);

   return time_elapsed;
}

void
display_errMsg(clock_t start, char *msg)
{
   long interval;

   end = clock();

   interval = display_interval(start, end);
   
   printf("Status : Message [%s]", msg);

   printf("\n\n<<< parser job has been ended : time elapsed - %9ld >>>\n\n", interval);

}

char *trim(char *buf, int size)
{
   char *temp;
   char temp_buf[size];
   int i = 0, j = 0;

   memset(temp, 0, size);

   
   for (i = 0; i < size; i++)
   {
      if (buf[i] != ' ')
      temp[j++] = buf[i];
   }

   strcpy(buf, temp);

   return buf;
}

int getDay()
{
   time_t   tt;
   struct tm *tm;

   tt = time(NULL);
   tm = localtime(&tt);

   return tm->tm_mday;
}

int getHour()
{
   time_t  tt;
   struct tm *tm;

   tt = time(NULL);
   tm = localtime(&tt);

   return tm->tm_hour;
}

int getMin()
{

   time_t  tt;
   struct tm *tm;

   tt = time(NULL);
   tm = localtime(&tt);

   return tm->tm_min;
}

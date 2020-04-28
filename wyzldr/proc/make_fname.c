#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void main(int argc, char **argv)
{
   int sum;
   

   sum = make_time(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
   printf("sum is %d, %x\n", sum, sum);

}

int getYear()
{
   time_t tt;
   struct tm *tm;

   tt = time(NULL);
   tm = localtime(&tt);

   return tm->tm_year-100;
}

int getMonth()
{  
   time_t tt;
   struct tm *tm;
   
   tt = time(NULL);
   tm = localtime(&tt);
   
   return tm->tm_mon;
}

int getDay()
{  
   time_t tt;
   struct tm *tm;
   
   tt = time(NULL);
   tm = localtime(&tt);
   
   return tm->tm_mday;
}

int getHour()
{  
   time_t tt;
   struct tm *tm;
   
   tt = time(NULL);
   tm = localtime(&tt);
   
   return tm->tm_hour;
}

int getMin()
{
   time_t tt;
   struct tm *tm;

   tt = time(NULL);
   tm = localtime(&tt);

   return tm->tm_min;
}

int getSec()
{

   time_t tt;
   struct tm *tm;

   tt = time(NULL);
   tm = localtime(&tt);

   return tm->tm_sec;
}

int make_time(int year, int month, int day, int hour, int min)
{
   //int year;
   //int month;
   //int day;
   //int hour;
   //int min;
   int sec;
   int sum = 0;
   int i;
   
   //year = 7;
   //month = 5;
   //day = 1;
   //hour = 19;
   //min = 27;

printf("%d, %d, %d, %d, %d\n", getYear(), getMonth(), getDay(), getHour(), getMin());
   /*year = getYear();

   month = getMonth();
   day = getDay();
   hour = getHour();
   min = getMin();*/
   sec = getSec();

   for (i = 0; i < year; i++)
   {
      if ((((i+2000) % 4) == 0) && (((i+2000) % 100) != 100) || (((i+2000) % 400) == 0))
      {
         sum += 31622400;
      } else {
          sum += 31536000; 
      }
   }

   for (i = 1; i <= month; i++)
   {
      switch (i) 
      {
          case 1: sum += 2678400; break;
          case 2: 
                 if ((((year+2000) % 4) == 0) && (((year+2000) % 100) != 100) || (((year+2000) % 400) == 0))
                    sum += 2505600;
                 else sum += 2419200;
                 break;
          case 3: sum += 2678400; break;
          case 4: sum += 2592000; break;
          case 5: sum += 2678400; break;
          case 6: sum += 2592000; break;
          case 7: sum += 2678400; break;
          case 8: sum += 2678400; break;
          case 9: sum += 2592000; break;
          case 10: sum += 2678400; break;
          case 11: sum += 2592000; break;
          case 12: sum += 2678400; break;
      }
   } 

   sum += ((day - 1) * 24 * 3600);

   sum += (hour * 3600);

   sum += ((min-1) * 60);

   return sum;
}

#include <sys/types.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>

#define UPCASE(c) (( (c)>='a' && (c)<='z') ? (c)-('a'-'A') : (c) )

int minTerms, maxTerms, tryyn;

/*
void daemon()
{
   pid_t   pid;
   int     pid_rtn = 0;

   if ((pid = fork()) < 0)
   {
      exit(0);

   } else if (pid != 0) {
             exit(0);
   }

   chdir("/");
   setsid();

}
*/

void getEnv(void)
{
   FILE *inputFile;
   int bufsize = 1024;
   char buf[bufsize];
   char *splitItem, *splitValue;
   char splitchar[] = {"="};

   if ((inputFile = fopen("./daemon.properties", "r")) != NULL)
   {
      while (fgets(buf, bufsize, inputFile) != NULL)
      {
         if (buf[0] != '#')
         {
            splitItem = strtok(buf, splitchar);
            splitValue = strtok(NULL, splitchar);
            if (strcmp(splitItem, "minTerms") == 0) minTerms = atoi(splitValue);
            else if (strcmp(splitItem, "maxTerms") == 0) maxTerms = atoi(splitValue);
			else if (strcmp(splitItem, "tryYn") == 0) tryyn = atoi(splitValue);
         }
      }
   } else {
            minTerms = 10;
            maxTerms = 180; 
			tryyn = 7;
   }
}

/*
int main(int argc, char **argv)
{
   int min, sec;
   int i, terms, lastsec, first_flag = 1;
   int interval = 0;
   char param[4];
   char filename[20];
   char hexaname[20];
   char buf[256];
   FILE *input1;

   getEnv();

   if ((input1 = fopen("./lastsec", "r")) != NULL)
	   while ((fgets(buf, 256, input1)) != NULL)
		   lastsec = atoi(buf);
   else
	    lastsec = 0;

   lastsec += 60;

   fclose(input1);

   memset(param, 0, sizeof(param));
   if (argc > 1) strcpy(param, argv[1]);
   else strcpy(param, "0");

   daemon();

   while(1) 
   {
      min = getMin();
      sec = getSec();

      printf("current sec:%d, hexaname:%x\n", sec, lastsec);

		  if (strcmp(param, "1") == 0)
		  {
			   sprintf(filename, "%x", lastsec);
		  } else {
			       if (first_flag == 1)
				     {
				        if (sec == 0) lastsec = make_time();
                                        sprintf(filename, "%x", lastsec);
				        first_flag = 0;
				     } else {
					          sprintf(filename, "%x", lastsec);
				     }
     }
     for(i = 0; i < strlen(filename); i++) hexaname[i] = toupper(filename[i]);
     hexaname[i] = '\0';

		 ftpFile(hexaname);

     if (checkFile(hexaname))
     {
        transFile(hexaname, lastsec);
        interval = 0;
        printf("hexaname:%x work complete\n", lastsec);
			  lastsec += 60;
	 } else {
            interval++;
            printf("file not found...%dth retry\n", interval);
            if (interval == tryyn)
            {
               interval = 0;
               lastsec += 60;
            }
     }

     sleep(10);
   }
}
*/

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

int make_time(void)
{
   int year;
   int month;
   int day;
   int hour;
   int min;
   int sec;
   int sum = 0;
   int i;
   
   year = getYear();
   month = getMonth();
   day = getDay();
   hour = getHour();
   min = getMin();
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

int checkFile(char *filename)
{
   int fileCnt = 0;
   int transChk = 0;
   
   DIR *dirp;
   struct dirent *dir;

   dirp = opendir(".");

   for(dir = readdir(dirp); dir != NULL; dir = readdir(dirp))
   {
      if (strlen(dir->d_name) > 2)
      {
         if (strstr(dir->d_name, filename) != NULL)
         {
            /*transChk = transFile(dir->d_name);
            
            if (transChk == 0) 
               printf("<<< file transfer fail!! - check it your bfr file >>>\n");
            else 
                remove(dir->d_name); */
               
            fileCnt++;
         }
      }
   }
   
   closedir(dirp);
   
   if (fileCnt > 0)
      return 1;
   else 
       return 0;
}

int transFile(char *hexaname, int lastsec)
{
   char cmd[1024];
   int hour, min;

   hour = getHour();
   min = getMin();
   memset(cmd, 0, 1024);

//  putenv("export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$ORACLE_HOME/lib32:$ORACLE_HOME/rdbms/lib32:/usr/lib");

//   sprintf(cmd, "cd /data2/oneview/bin; /data2/oneview/bin/run_bfr.sh %s-60.bfr %d >> /data2/oneview/sqlloader/log/work_time", hexaname, lastsec);

//   system(cmd);
}

int ftpFile(char *filename)
{
	char cmd[1024];

	memset(cmd, 0, sizeof(cmd));

//	sprintf(cmd, "cd /data2/oneview/bin; /data2/oneview/bin/get_bfr.sh %s-60.bfr >> /data2/oneview/sqlloader/log/work_time", filename);

//	system(cmd);
}

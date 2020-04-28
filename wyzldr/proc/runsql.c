/*******************************************************************************
 *  Copyrights(c) 2007~ Modern Limes Technology(MLT) Co., Ltd. Seoul Korea
 *  
 * All rights are reserved. This is unpublished proprietary source code of MLT.
 * The copyright notice does not evidence any actual publication of such source
 * code.
 * 
 *      Subject : SIP Packet's Uploader, make SQL-statement, executed 
 *                SQL-statement module 
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

/*******************************************************************************
 * PRIVATE VARIABLES
 ******************************************************************************/

/*******************************************************************************
 * IMPLEMENTATION OF INTERFACE FUNCTIONS
 ******************************************************************************/

/*******************************************************************************
 * IMPLEMENTATION OF PUBLIC FUNCTIONS
 ******************************************************************************/

/*******************************************************************************
 * NAME : parser's make sql statement function
 * ARGUMENT : DBCOLINFO, int
 * RETURNS/SIDE-EFFECTS : DBCOLINFO
 ******************************************************************************/
void make_sql(DBCOLINFO new, FILE *fp, int rownum)
{
   char stmt[1024];
   
   memset(stmt, 0, 1024);

   if (strcmp(new.cseq_mtd_col, "REGISTER") == 0 || strcmp(new.cseq_mtd_col, "OPTIONS") == 0 || strcmp(new.cseq_mtd_col, "PING") == 0)
   {
      fprintf(fp, "INSERT INTO DAY_REGI_TMP VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, %s, TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'))\n",
                                                new.packetno_col, new.datestr_col, 
                                                new.ipsrc_col, new.ipdst_col, 
                                                new.srcport_col, new.dstport_col, 
                                                new.method_col, new.to_num_col, 
                                                new.to_domain_col, new.from_num_col, 
                                                new.from_domain_col, new.callid_str_col, 
                                                new.cseq_num_col, new.cseq_mtd_col, 
                                                new.user_agent_col, new.srcname_col, 
                                                new.offsetnum_col, new.length_col, new.expire_col);
   } else if (strlen(new.to_num_col) < 1 && strlen(new.from_num_col) < 1) {
      fprintf(fp, "INSERT INTO DAY_OTHER VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, %s, TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'))\n",
                                                new.packetno_col, new.datestr_col, 
                                                new.ipsrc_col, new.ipdst_col, 
                                                new.srcport_col, new.dstport_col, 
                                                new.method_col, new.to_num_col, 
                                                new.to_domain_col, new.from_num_col, 
                                                new.from_domain_col, new.callid_str_col, 
                                                new.cseq_num_col, new.cseq_mtd_col, 
                                                new.user_agent_col, new.srcname_col, 
                                                new.offsetnum_col, new.length_col, new.expire_col);
   } else if (strcmp(new.cseq_mtd_col, "REGISTER") != 0 && strcmp(new.cseq_mtd_col, "OPTIONS") != 0 && strcmp(new.cseq_mtd_col, "PING") != 0) {
      fprintf(fp, "INSERT INTO DAY_CALL_TMP VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %d, %d, %s, TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'))\n",
                                                new.packetno_col, new.datestr_col, 
                                                new.ipsrc_col, new.ipdst_col, 
                                                new.srcport_col, new.dstport_col, 
                                                new.method_col, new.to_num_col, 
                                                new.to_domain_col, new.from_num_col, 
                                                new.from_domain_col, new.callid_str_col, 
                                                new.cseq_num_col, new.cseq_mtd_col, 
                                                new.user_agent_col, new.srcname_col, 
                                                new.offsetnum_col, new.length_col, new.expire_col);
  }
}

int make_stat_sql(STATPROTOCOL temp, char *srcname)
{
   char stat_sql[1024];
   char cmd[1024];
   int result = 0;
   FILE *fp;

   sprintf(stat_sql, "INSERT INTO STAT_TOTAL VALUES(%d, %d, %d, %d, TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'), '%s', 'N')",
           temp.tot_cnt, temp.udp_cnt, temp.tcp_cnt, temp.sip_cnt, srcname); 

   fp = fopen("../sqlloader/data/stat_total.dat", "w");
   fprintf(fp, "%s", stat_sql);
   fclose(fp);

   //sprintf(cmd, "sqlldr voip/dusrnth control=../sqlloader/ctl/stat_total.ctl data=../sqlloader/data/stat_total.dat");
   sprintf(cmd, "./batch_exec ../sqlloader/data/stat_total.dat");

//   system(cmd);

   return result;
}

int make_tcps_sql(TCPPROTOCOL tcps)
{
   char stat_sql[1024];
   char cmd[1024];
   int result = 0;
   FILE *fp;

   sprintf(stat_sql, "INSERT INTO TCP_STAT VALUES(%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'))",
tcps.tcp1, tcps.tcp2, tcps.tcp3, tcps.tcp4, tcps.tcp5, tcps.tcp6, tcps.tcp7, tcps.tcp8, tcps.tcp9, tcps.tcp10,
tcps.tcp11, tcps.tcp12, tcps.tcp13, tcps.tcp14, tcps.tcp15, tcps.tcp16, tcps.tcp17, tcps.tcp18, tcps.tcp19, tcps.tcp20,
tcps.tcp21, tcps.tcp22, tcps.tcp23, tcps.tcp24, tcps.tcp25, tcps.tcp26, tcps.tcp27, tcps.tcp28, tcps.tcp29, tcps.tcp30,
tcps.tcp31, tcps.tcp32, tcps.tcp33, tcps.tcp34, tcps.tcp35, tcps.tcp36, tcps.tcp37, tcps.tcp38, tcps.tcp39, tcps.tcp40,
tcps.tcp41, tcps.tcp42, tcps.tcp43, tcps.tcp44, tcps.tcp45, tcps.tcp46, tcps.tcp47, tcps.tcp48, tcps.tcp49, tcps.tcp50,
tcps.tcp51, tcps.tcp52, tcps.tcp53, tcps.tcp54, tcps.tcp55, tcps.tcp56, tcps.tcp57, tcps.tcp58, tcps.tcp59, tcps.tcp60,
tcps.tcp61, tcps.tcp62, tcps.tcp63, tcps.tcp64, tcps.tcp65, tcps.tcp66, tcps.tcp67, tcps.tcp68, tcps.tcp69, tcps.tcp70,
tcps.tcp71, tcps.tcp72, tcps.tcp73, tcps.tcp74, tcps.tcp75, tcps.tcp76, tcps.tcp77, tcps.tcp78, tcps.tcp79, tcps.tcp80,
tcps.tcp81, tcps.tcp82, tcps.tcp83, tcps.tcp84, tcps.tcp85, tcps.tcp86, tcps.tcp87, tcps.tcp88, tcps.tcp89, tcps.tcp90,
tcps.tcp91, tcps.tcp92, tcps.tcp93, tcps.tcp94, tcps.tcp95, tcps.tcp96, tcps.tcp97, tcps.tcp98, tcps.tcp99, tcps.tcp100,
tcps.tcp101, tcps.tcp102, tcps.tcp103, tcps.tcp104, tcps.tcp105, tcps.tcp106, tcps.tcp107, tcps.tcp108, tcps.tcp109, tcps.tcp110,
tcps.tcp111, tcps.tcp112, tcps.tcp113, tcps.tcp114, tcps.tcp115, tcps.tcp116, tcps.tcp117, tcps.tcp118, tcps.tcp119, tcps.tcp120,
tcps.tcp121, tcps.tcp122, tcps.tcp123, tcps.tcp124, tcps.tcp125, tcps.tcp126, tcps.tcp127, tcps.tcpoth);

   fp = fopen("../sqlloader/data/tcp_stat.dat", "w");
   fprintf(fp, "%s", stat_sql);
   fclose(fp);

   //sprintf(cmd, "sqlldr voip/dusrnth control=../sqlloader/ctl/tcp_stat.ctl data=../sqlloader/data/tcp_stat.dat");
   sprintf(cmd, "./batch_exec ../sqlloader/data/tcp_stat.dat");

//   system(cmd);

   return result;
}

int make_mtds_sql(METHODCNT temp)
{
   char stat_sql[1024];
   char cmd[1024];
   int result = 0;
   FILE *fp;

   sprintf(stat_sql, "INSERT INTO MTDS_STAT VALUES(%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'))",
           temp.invite_cnt, temp.ack_cnt, temp.bye_cnt, temp.cancel_cnt, temp.register_cnt, temp.option_cnt,
           temp.info_cnt, temp.message_cnt, temp.update_cnt, temp.refer_cnt, temp.prack_cnt, temp.subscribe_cnt,
           temp.unsubscribe_cnt, temp.notify_cnt); 

   fp = fopen("../sqlloader/data/mtds_stat.dat", "w");
   fprintf(fp, "%s", stat_sql);
   fclose(fp);

   //sprintf(cmd, "sqlldr voip/dusrnth control=../sqlloader/ctl/mtds_stat.ctl data=../sqlloader/data/mtds_stat.dat");
   sprintf(cmd, "./batch_exec ../sqlloader/data/mtds_stat.dat");

//   system(cmd);

   return result;
}

int make_msgs_sql(MESSAGECNT temp)
{

   char stat_sql[1024];
   char cmd[1024];
   int result = 0;
   FILE *fp;

   sprintf(stat_sql, "INSERT INTO MSGS_STAT VALUES(%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS'))",
           temp.cnt_100, temp.cnt_180, temp.cnt_181, temp.cnt_182, temp.cnt_183, temp.cnt_200, temp.cnt_202, temp.cnt_300,
           temp.cnt_301, temp.cnt_302, temp.cnt_305, temp.cnt_380, temp.cnt_400, temp.cnt_401, temp.cnt_402, temp.cnt_403,
           temp.cnt_404, temp.cnt_405, temp.cnt_406, temp.cnt_407, temp.cnt_408, temp.cnt_410, temp.cnt_413, temp.cnt_414,
           temp.cnt_415, temp.cnt_416, temp.cnt_420, temp.cnt_421, temp.cnt_422, temp.cnt_423, temp.cnt_429, temp.cnt_480,
           temp.cnt_481, temp.cnt_483, temp.cnt_484, temp.cnt_485, temp.cnt_486, temp.cnt_487, temp.cnt_488, temp.cnt_489,
           temp.cnt_491, temp.cnt_493, temp.cnt_494, temp.cnt_500, temp.cnt_501, temp.cnt_502, temp.cnt_503, temp.cnt_504,
           temp.cnt_505, temp.cnt_513, temp.cnt_580, temp.cnt_600, temp.cnt_603, temp.cnt_604, temp.cnt_607, temp.cnt_687); 

   fp = fopen("../sqlloader/data/msgs_stat.dat", "w");
   fprintf(fp, "%s", stat_sql);
   fclose(fp);

   //sprintf(cmd, "sqlldr voip/dusrnth control=../sqlloader/ctl/msgs_stat.ctl data=../sqlloader/data/msgs_stat.dat");
   sprintf(cmd, "./batch_exec ../sqlloader/data/msgs_stat.dat");

//   system(cmd);
}

int make_all_sql(char *reginame, char *callname, char *othername)
{
   char registmt[1024];
   char callstmt[1024];
   char otherstmt[1024];
   char allstmt[4096];

//   sprintf(registmt, "sqlldr voip/dusrnth errors=100000 direct=true silent=header log=../sqlloader/log/regi_%d.log bad=../sqlloader/log/regi_%d.bad control=../sqlloader/ctl/regi/regi_%d.ctl data=%s", getDay(), getDay(), getDay(), reginame);
   sprintf(registmt, "sqlldr voip/dusrnth errors=10000 silent=header log=../sqlloader/log/regi_%d.log bad=../sqlloader/log/regi_%d.bad control=../sqlloader/ctl/regi/regi_%d.ctl data=%s", getDay(), getDay(), getDay(), reginame);

 //  sprintf(callstmt, "sqlldr voip/dusrnth errors=100000 direct=true silent=header log=../sqlloader/log/call_%d.log bad=../sqlloader/log/call_%d.bad control=../sqlloader/ctl/call/call_%d.ctl data=%s", getDay(), getDay(), getDay(), callname);
   sprintf(callstmt, "sqlldr voip/dusrnth errors=10000 silent=header log=../sqlloader/log/call_%d.log bad=../sqlloader/log/call_%d.bad control=../sqlloader/ctl/call/call_%d.ctl data=%s", getDay(), getDay(), getDay(), callname);
   
  // sprintf(otherstmt, "sqlldr voip/dusrnth errors=100000 direct=true silent=header log=../sqlloader/log/other_%d.log bad=../sqlloader/log/other_%d.bad control=../sqlloader/ctl/other/other_%d.ctl data=%s", getDay(), getDay(), getDay(), othername);
   sprintf(otherstmt, "sqlldr voip/dusrnth errors=10000 silent=header log=../sqlloader/log/other_%d.log bad=../sqlloader/log/other_%d.bad control=../sqlloader/ctl/other/other_%d.ctl data=%s", getDay(), getDay(), getDay(), othername);

   //sprintf(allstmt, "%s; %s; %s;", registmt, callstmt, otherstmt);
   sprintf(allstmt, "%s; %s;", registmt, callstmt);

//   system(allstmt);

   return;
}

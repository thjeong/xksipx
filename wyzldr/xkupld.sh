#!/bin/ksh

export NOWDAY=`date "+%Y_%m_%d"`
export NOWTIME=`date "+%H:%M:%S"`
export FACTORY=/home/oracle/wyzldr
export BFRPATH=/home/oracle/wyzldr
export INDEX=1

echo "$NOWDAY $NOWTIME : WYZBFRLD started." >> $FACTORY/LOG/$NOWDAY.log

while [ $INDEX -gt 0 ];
do

cd $BFRPATH

COUNT=`ls *.REGI | wc -l`

        if [ $COUNT -gt 0 ]; then
                FILENAME=`ls *.REGI | head -1 | sed 's/.REGI//g'`
                CURDATE=`tail -1 $FILENAME.REGI | awk -F- '{print $4}'`
                NOWDAY=`date "+%Y_%m_%d"`
                NOWTIME=`date "+%H:%M:%S"`
                LOGFILE=$FACTORY/LOG/$NOWDAY.log

                tail -1 $FILENAME.REGI | awk -F\` '{print "Current file for "substr($4,0,16)}' >> $LOGFILE

                echo "$NOWDAY $NOWTIME : [START] $FILENAME.REGI loading..." >> $LOGFILE
                #sqlldr userid=voip/dusrnth silent=header,feedback readsize=20480000 bindsize=20480000 date_cache=81920 rows=10240 log=$BFRPATH/LOG/$FILENAME.REGI.LOG bad=$BFRPATH/REGI.BAD control=$FACTORY/CONTROL/REGI_$CURDATE.CTL data=$FILENAME.REGI _display_exitcode=true >> $LOGFILE
                #sqlldr userid=voip/dusrnth silent=header,feedback readsize=4096000 bindsize=4096000 date_cache=8192 rows=1024 log=$BFRPATH/LOG/$FILENAME.REGI.LOG bad=$BFRPATH/REGI.BAD control=$FACTORY/CONTROL/REGI_$CURDATE.CTL data=$FILENAME.REGI _display_exitcode=true >> $LOGFILE
                sqlldr userid=voip/dusrnth silent=header,feedback direct=true log=$BFRPATH/LOG/$FILENAME.REGI.LOG bad=$BFRPATH/REGI.BAD control=$FACTORY/CONTROL/REGI_$CURDATE.CTL data=$FILENAME.REGI _display_exitcode=true >> $LOGFILE
		cat $BFRPATH/LOG/$FILENAME.REGI.LOG | grep "successfully loaded" >> $LOGFILE
		cat $BFRPATH/LOG/$FILENAME.REGI.LOG | grep "not loaded due to data errors" >> $LOGFILE
		cat $BFRPATH/LOG/$FILENAME.REGI.LOG | grep "Elapsed time" >> $LOGFILE

                echo "$NOWDAY $NOWTIME : [START] $FILENAME.CALL loading..." >> $LOGFILE
                #sqlldr userid=voip/dusrnth silent=header,feedback readsize=20480000 bindsize=20480000 date_cache=81920 rows=10240 log=$BFRPATH/LOG/$FILENAME.CALL.LOG bad=$BFRPATH/CALL.BAD control=$FACTORY/CONTROL/CALL_$CURDATE.CTL data=$FILENAME.CALL _display_exitcode=true >> $LOGFILE
                #sqlldr userid=voip/dusrnth silent=header,feedback readsize=4096000 bindsize=4096000 date_cache=8192 rows=1024 log=$BFRPATH/LOG/$FILENAME.CALL.LOG bad=$BFRPATH/CALL.BAD control=$FACTORY/CONTROL/CALL_$CURDATE.CTL data=$FILENAME.CALL _display_exitcode=true >> $LOGFILE
                sqlldr userid=voip/dusrnth silent=header,feedback direct=true log=$BFRPATH/LOG/$FILENAME.CALL.LOG bad=$BFRPATH/CALL.BAD control=$FACTORY/CONTROL/CALL_$CURDATE.CTL data=$FILENAME.CALL _display_exitcode=true >> $LOGFILE
		cat $BFRPATH/LOG/$FILENAME.CALL.LOG | grep "successfully loaded" >> $LOGFILE
		cat $BFRPATH/LOG/$FILENAME.CALL.LOG | grep "not loaded due to data errors" >> $LOGFILE
		cat $BFRPATH/LOG/$FILENAME.CALL.LOG | grep "Elapsed time" >> $LOGFILE

                NOWDAY=`date "+%Y_%m_%d"`
                NOWTIME=`date "+%H:%M:%S"`
                REGIRESULT=`cat $BFRPATH/LOG/$FILENAME.REGI.LOG | grep Row | grep success | awk '{print $1}'`
                CALLRESULT=`cat $BFRPATH/LOG/$FILENAME.CALL.LOG | grep Row | grep success | awk '{print $1}'`

                if [ $REGIRESULT -a $CALLRESULT -a $REGIRESULT -gt 0 -a $CALLRESULT -gt 0 ]; then

                	rm -f $BFRPATH/$FILENAME.REGI
                	rm -f $BFRPATH/$FILENAME.CALL
                	rm -f $BFRPATH/$FILENAME-60.BFR 
                	echo "$NOWDAY $NOWTIME : [COMPLETE] $FILENAME loaded." >> $LOGFILE 

                	sqlplus -S voip/dusrnth << EOF
                       		UPDATE STAT_TOTAL SET PROC_FG = 'N' WHERE FILE_NM = '$FILENAME-60.BFR';
				COMMIT;
EOF
                else
                        echo "$NOWDAY $NOWTIME : [ERROR] $FILENAME has not loaded!!! " >> $LOGFILE
                        exit
                fi
        else
        #        echo "$NOWDAY $NOWTIME : [COMPLETE] $FILENAME 0 loaded.(cause:no data)" >> $LOGFILE 
		sleep 10
        fi
done

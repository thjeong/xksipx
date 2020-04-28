#!/bin/ksh

export NOWDAY=`date "+%Y_%m_%d"`
export NOWTIME=`date "+%H:%M:%S"`
export FACTORY=/usr/local/factory/wyzldr
export BFRPATH=/usr/local/factory/wyzldr
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

                echo "Logfile : $LOGFILE"
                echo "Curdate : $CURDATE"

                echo "$NOWDAY $NOWTIME : [START] $FILENAME.REGI loading..." >> $LOGFILE

                sqlldr userid=voip/dusrnth silent=feedback readsize=4096000 bindsize=4096000 date_cache=8192 rows=1024 log=$BFRPATH/LOG/$FILENAME.REGI.LOG bad=$BFRPATH/REGI.BAD control=$FACTORY/CONTROL/REGI_$CURDATE.CTL data=$FILENAME.REGI _display_exitcode=true >> $LOGFILE
                echo "$NOWDAY $NOWTIME : [START] $FILENAME.CALL loading..." >> $LOGFILE
                sqlldr userid=voip/dusrnth silent=feedback readsize=4096000 bindsize=4096000 date_cache=8192 rows=1024 log=$BFRPATH/LOG/$FILENAME.CALL.LOG bad=$BFRPATH/CALL.BAD control=$FACTORY/CONTROL/CALL_$CURDATE.CTL data=$FILENAME.CALL _display_exitcode=true >> $LOGFILE

                NOWDAY=`date "+%Y_%m_%d"`
                NOWTIME=`date "+%H:%M:%S"`
                REGIRESULT=`cat $BFRPATH/$FILENAME.REGI.LOG | grep Row | grep success | awk '{print $1}'`
                CALLRESULT=`cat $BFRPATH/$FILENAME.CALL.LOG | grep Row | grep success | awk '{print $1}'`

                echo $NOWDAY
                echo $NOWTIME

                if [ $REGIRESULT -a $CALLRESULT -a $REGIRESULT -gt 0 -a $CALLRESULT -gt 0 ]; then

                echo    rm $BFRPATH/$FILENAME.REGI
                echo    rm $BFRPATH/$FILENAME.CALL
                echo    rm $BFRPATH/$FILENAME-60.BFR 
                echo "$NOWDAY $NOWTIME : [COMPLETE] $FILENAME loaded." >> $LOGFILE 

                sqlplus -S voip/dusrnth << EOF
                        UPDATE STAT_TOTAL_TEST SET PROC_FG = 'Y' WHERE FILE_NM = '$FILENAME-60.BFR';
EOF
	exit
                else
                        echo "$NOWDAY $NOWTIME : [ERROR] $FILENAME has not loaded!!! " >> $LOGFILE
                        sleep 60
                fi
        else
                echo "$NOWDAY $NOWTIME : [COMPLETE] $FILENAME 0 loaded.(cause:no data)" >> $LOGFILE 
        fi
done

#!/bin/ksh

export NLS_LANG=american_america.KO16KSC5601
export LANGUAGE="ko_KR"
export LC_ALL="ko_KR"
LANG=ko_KR
export LANG

NOWDAY=`date "+%Y_%m_%d"`
NOWTIME=`date "+%H:%M:%S"`
FACTORY=/home/oracle/factory
echo $NOWDAY" "$NOWTIME" : BWCDRLD started." >> $FACTORY/LOG/$NOWDAY.log
INDEX=1

while [ $INDEX -gt 0 ];
do

CDRPATH=/data/CDR

cd $CDRPATH

COUNT=`ls BW-CDR*.csv | wc -l`
if [ $COUNT -gt 0 ]; then
		FILENAME=`ls BW-CDR*.csv | head -1`
		CURDATE=`echo $FILENAME | cut -c 8-15`
		CURDATEMIN=`echo $FILENAME | cut -c 8-19`
		NOWDAY=`date "+%Y_%m_%d"`
		NOWTIME=`date "+%H:%M:%S"`
		LOGFILE=$FACTORY/LOG/$NOWDAY.log

		echo "Logfile : $LOGFILE"
	echo "Curdate : $CURDATE"

		echo $NOWDAY" "$NOWTIME" : [START] "$FILENAME" loading..." >> $LOGFILE
	export CURDATE
	export FILENAME
		mv $CDRPATH/$FILENAME $CDRPATH/$FILENAME.in

	export sip_prefix=`sqlplus sipcdr/imsi00 << EOF | grep \! | grep -v Usage | sed 's/\!/\n/g'
		set heading off;
		select prefix||'!'||company from sip_prefix where company is not null;
EOF`

		if [ sip_prefix ]; then
				cat $CDRPATH/$FILENAME.in | awk -F, -f $FACTORY/bwcdr.prog | awk -F, -f $FACTORY/iplink.prog > $CDRPATH/$FILENAME.awked

		AWKED_LINES=`cat $CDRPATH/$FILENAME.awked | wc -l`
		if [ $AWKED_LINES -gt 0 ]; then

	   			sqlldr userid=sipcdr/imsi00 control=$FACTORY/bwcdr.ctl data=$CDRPATH/$FILENAME.awked bad=$CDRPATH/FAULT/$FILENAME.fault log=$CDRPATH/$FILENAME.log direct=true _display_exitcode=true >> $LOGFILE

	   			sqlldr userid=qosuser/qosuser123@zealot control=$FACTORY/zealotcdr.ctl data=$CDRPATH/$FILENAME.awked bad=$CDRPATH/FAULT/$FILENAME.fault log=$CDRPATH/$FILENAME.zealot.log _display_exitcode=true >> $LOGFILE
		
				NOWDAY=`date "+%Y_%m_%d"`
				NOWTIME=`date "+%H:%M:%S"`
				LOGRESULT=`cat $CDRPATH/$FILENAME.log | grep Row | grep success | awk '{print $1}'`

				echo $NOWDAY
				echo $NOWTIME
				echo $LOGRESULT

				if [ $LOGRESULT -a $LOGRESULT -gt 0 ]; then
						if [ ! -d $CDRPATH/$CURDATE ]; then
								mkdir $CDRPATH/$CURDATE
						fi

			   		mv $CDRPATH/$FILENAME.in $CDRPATH/$CURDATE/$FILENAME >> $LOGFILE
			   		mv $CDRPATH/$FILENAME.log $CDRPATH/$CURDATE/$FILENAME.log >> $LOGFILE
			   		mv $CDRPATH/$FILENAME.zealot.log $CDRPATH/$CURDATE/$FILENAME.zealot.log >> $LOGFILE
					mv $CDRPATH/$FILENAME.awked $CDRPATH/$CURDATE/$FILENAME.awked >> $LOGFILE
			   		echo $NOWDAY" "$NOWTIME" : [COMPLETE] "$FILENAME" loaded." >> $LOGFILE 

					sqlplus -S sipcdr/imsi00 << EOF
						insert into uploaded_file values ('$CURDATEMIN', '$FILENAME','N','BRW');
EOF
				else			
			   		echo $FILENAME
			   		echo "ls -l $CDRPATH/$FILENAME.in"
			   		ls -al $CDRPATH/$FILENAME.in

			   		mv $CDRPATH/$FILENAME.in $CDRPATH/$FILENAME >> $LOGFILE
			   		echo "$NOWDAY $NOWTIME : [ERROR] $FILENAME has not loaded!!! " >> $LOGFILE
			   		sleep 10
				fi
		else
					mv $CDRPATH/$FILENAME.in $CDRPATH/$CURDATE/$FILENAME >> $LOGFILE
			mv $CDRPATH/$FILENAME.awked $CDRPATH/$CURDATE/$FILENAME.awked >> $LOGFILE
	   			 	echo $NOWDAY" "$NOWTIME" : [COMPLETE] "$FILENAME" 0 loaded.(cause:awked line is 0)" >> $LOGFILE 
		fi
	else
	   		   	echo $NOWDAY" "$NOWTIME" : [ERROR] SIP_PREFIX query failed!!!" >> $LOGFILE 
		fi
else
   	mv $CDRPATH/$FILENAME.in $CDRPATH/$CURDATE/$FILENAME >> $LOGFILE
	mv $CDRPATH/$FILENAME.awked $CDRPATH/$CURDATE/$FILENAME.awked >> $LOGFILE
	sleep 10

fi

done

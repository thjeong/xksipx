#!/bin/sh 
# 
# ./moncore.sh > /dev/null 2>&1 & (sh) 
# ./moncore.sh >& /dev/null & (csh) 
# 
# 
#debugger=dbx 
debugger=/usr/local/bin/gdb
while : 
do 
if [ -f core ] 
then 
now=`date '+%Y%m%d-%H%M%S'` 
appname=`file core | sed "s/.*'\(.*\)'.*/\1/g"` 
newcore=core.$appname.$now.core 
mv core $newcore 
text=core.$appname.$now.txt 
( 
 echo "" 
 echo "" 
 echo "" 
 echo "where" 
 echo "quit" 
 ) | $debugger $appname $newcore > $text 
fi 
sleep 5 
done 

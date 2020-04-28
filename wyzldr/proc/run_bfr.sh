#!/bin/sh

export PATH=$PATH:.
export LD_LIBRARY_PATH=$ORACLE_HOME/lib32:$ORACLE_HOME/rdbms/lib32:/usr/lib

#if [ -f $1 ]; then
#   echo "========================================================"
#   echo " File Name : " $1
#   echo " Work Date : " `date`
#   echo "========================================================"
#fi

echo "  Parsing & Upload Start - " `date`
start_time=`date +%s`

if [ -f $1 ]; then
   echo "========================================================="
   echo " Work Date : " `date`
   ./make_token1 $1 out > do_list
   echo "========================================================="
   echo " Work Date : " `date`
   #/bin/mv $1.txt ../bfrfile/$1
   /bin/rm $1.txt
   /bin/rm -f $1
fi

echo "  Parsing & Upload End - " `date`
end_time=`date +%s`
let time_diff=$end_time-$start_time

if [ $time_diff -lt 5 ]
then
   echo "  Parsing : Fail "
else
    echo "  Parsing : Success "
fi

file_size=`ls -la ./do_list | awk '{ print $5 }'`
if [ $file_size -lt 50 ]
then
   echo "  Loading : Fail "
else
    echo "  Loading : Success "
    echo $2 > ./lastsec
fi
echo "========================================================"

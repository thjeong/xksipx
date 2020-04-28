#!/bin/sh

export PATH=$PATH:.
export LD_LIBRARY_PATH=$ORACLE_HOME/lib32:$ORACLE_HOME/rdbms/lib32:/usr/lib

echo "========================================================"
echo " File Name : " $1
echo " Work Date : " `date`
echo "========================================================"
/usr/bin/ftp -in 33.100.3.33 << EOF
user ftpuser dpqxnl
binary
lcd /data2/oneview/src/current_ver
get $1
EOF

echo " Work Date : " `date`

#!/bin/ksh

while [ true ];
do
	ls -l *.BFR *.REGI *.CALL 2> /dev/null
	usleep 500000;
	clear
done

#!/bin/ksh

gwfile=$1

IFS=','
total=0
defcount=`pfctl -sr | grep -v "route-to" | egrep "lanlow|lan2low" | wc -l`
total=$defcount
echo -n "{"
while read g i
do
   count=`pfctl -sr | grep "route-to $i" | wc -l`
   echo -n "\"$g\":$count,"
   total=$((total+count))
done < $gwfile
echo -n "\"defcount\":$defcount,"
echo -n "\"total\":$total"
echo "}"

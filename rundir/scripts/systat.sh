#!/bin/sh

cputemp=`systat -a -B sensors | awk '/cpu0\.temp0/ {print $2 }'`
if [[ $? -ne 0 ]];then
    cputemp=`systat -a -B sensors | awk '/ksmn0\.temp0/ {print $2 }'`
fi
cpuusage=`systat -a -B cpu | awk '/^[0-3]/ {gsub(/%/,"",$7); m+=$7; count++} END {printf "%s", m/count}'`

gwstats(){
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
}
rundir=$(dirname $0)
gwsubs=`gwstats $rundir/gateways.conf`
echo "{ \"cputemp\":$cputemp, \"cpuusage\":$cpuusage, \"gwsubs\":$gwsubs }"

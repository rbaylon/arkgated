#!/bin/sh

cputemp=`systat -a -B sensors | awk '/cpu0\.temp0/ {print $2 }'`
cpuusage=`systat -a -B cpu | awk '/^[0-3]/ {gsub(/%/,"",$7); m+=$7; count++} END {printf "%s", m/count}'`
total=`pfctl -sr | grep lanlow | wc -l`
globe=192.168.254.254
pldt=192.168.69.1
defgw=`cat /etc/mygate`

gsub=`pfctl -sr | grep $globe | wc -l`
psub=`pfctl -sr | grep $pldt | wc -l`
defsub=`pfctl -sr | egrep "lan2low|lanlow" | grep -v route | wc -l`
case $defgw in
        "$globe")
                gsub=$((defsub+gsub))
                ;;
        "$pldt")
                psub=$((defsub+psub))
                ;;
esac
gwsubs="{\"globe\":$gsub,\"pldt\":$psub}"
echo "{ \"cputemp\":$cputemp, \"cpuusage\":$cpuusage, \"gwsubs\":$gwsubs }"

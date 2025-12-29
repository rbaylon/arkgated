#!/bin/sh

systat -a -B -d 5 queue | grep "lan " | grep -v "Plan" |\
awk 'BEGIN {
        printf "\{\"subs\"\:\{"
        }
        {if (match($10, /K/)){subs[$1]+=$10*1024} else if (match($10, /M/)) {subs[$1]+=$10*10240} else {subs[$1]+=$10}}
        END {
                for (s in subs){
                        bps=subs[s]*8
                        speed=bps "bps"
                        if(bps > 1000000){
                                mbps=bps/1000000.0
                                speed=mbps "Mbps"
                        } else if (bps > 1000) {
                                kbps=bps/1000
                                speed=kbps "Kbps"
                        }
                        cmd = "pfctl -sr | grep "s" | cut -d \" \" -f7"
                        userip=s
                        while ( ( cmd | getline ip ) > 0 ) {
                                userip=ip
                        }
                        close(cmd);
                        printf "\"%s\":\"%s\",", userip,speed
                }
                print "\}\}"
        }' | \
sed "s/,}/}/g"

#!/bin/sh

workdir=$(dirname $0)
passwd=$1
cd $workdir
echo "creating arkgate group"
groupadd arkgate
echo "done"

echo "Creating admin user..."
adduser -batch admin arkgate $passwd -unencrypted
echo "done"

cd /dev/
./MAKEDEV pppac1
./MAKEDEV pppac2
./MAKEDEV pppac3
./MAKEDEV pppac4
./MAKEDEV pppac5
./MAKEDEV pppac6
./MAKEDEV pppac7
echo "done"



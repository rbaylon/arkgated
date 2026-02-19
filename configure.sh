#!/bin/sh

workdir=$(dirname $0)
passwd=$1
cd $workdir
echo "Setting up system files..."
mv systemfiles/sysctl.conf /etc/
mv systemfiles/rc.conf.local /etc/
cp rc_arkgated /etc/rc.d/arkgated
chmod -v 755 /etc/rc.d/arkgated
echo "done"

echo "creating arkgate group"
groupadd arkgate
echo "done"

echo "Creating arkadmin user..."
adduser -batch arkadmin arkgate $passwd -unencrypted
echo "done"

echo "Installing arkgated"
mkdir "/usr/local/arkgate/arkgated"
go env -w GOBIN=/usr/local/arkgate/arkgated
echo "enabling arkgated to run on startup"
echo "arkgated_flags=\"-config ${workdir}/rundir/daemon.config\"" >> /etc/rc.conf.local
rcctl enable arkgated
rcctl start arkgated
cd /dev/
./MAKEDEV pppac1
./MAKEDEV pppac2
./MAKEDEV pppac3
./MAKEDEV pppac4
./MAKEDEV pppac5
./MAKEDEV pppac6
./MAKEDEV pppac7
echo "done"



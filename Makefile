app=arkgated
distdir=/usr/local/arkgate/${app}

build:
	go mod tidy
	go build -o ${app}

rc:
	install -m 755 systemfiles/rc.arkgated /etc/rc.d/${app}
	echo "${app} install in rc.d"
	echo "use rcctl enable|start ${app} to enable and start."

install:
	mkdir -p ${distdir}
	install -m 755 ${app} /usr/local/sbin/
	cp -r rundir ${distdir}/

dist:
	make install
	install -m 755 ${app} ${distdir}/
	install systemfiles/rc.arkgated ${distdir}/
	install systemfiles/sysctl.conf ${distdir}/
	cd ${distdir}
	cd ..
	tar -czvf ${app}.tar.gz ${app}
	ls -l ${app}.tar.gz

clean:
	rm -rf ${distdir}
	rm -f ${app}
	rm -f /etc/rc.d/${app}

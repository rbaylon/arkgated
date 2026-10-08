app=arkgated
version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
distdir=/usr/local/arkgate/${app}

build:
	git pull
	go mod tidy
	go build -ldflags "-s -w" -o ${app}

rc:
	install -m 755 rc.arkgated /etc/rc.d/${app}
	echo "${app} install in rc.d"
	echo "use rcctl enable|start ${app} to enable and start."

install:
	mkdir -p ${distdir}
	install -m 755 ${app} ${distdir}/
	cp -r rundir ${distdir}/

dist:
	make build
	make install
	install -m 755 rc.arkgated ${distdir}/
	tar -C /usr/local/arkgate/ -czvf /usr/local/arkgate/${app}-${version}.tar.gz ${app}
	ls -l /usr/local/arkgate/${app}-${version}.tar.gz

clean:
	rm -rf ${distdir}
	rm -f ${app}
	rm -f /etc/rc.d/${app}

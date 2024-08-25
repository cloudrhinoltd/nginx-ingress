
default:	build

clean:
	rm -rf Makefile objs

.PHONY:	default clean

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/sbin/nginx -t

	kill -USR2 `cat /./nginx.pid`
	sleep 1
	test -f /./nginx.pid.oldbin

	kill -QUIT `cat /./nginx.pid.oldbin`

.PHONY:	build install modules upgrade

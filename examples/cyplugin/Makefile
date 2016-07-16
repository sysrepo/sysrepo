love: libsysrepo-cyplugin.so
.PHONY: love

CFLAGS=-Wall -Wpedantic -std=gnu11 -Wno-strict-aliasing -g -O0 -fPIC -I../.. -I../../inc \
	`python2.7-config --cflags`

#	`python2.7 -c "import lxml; print \" \".join([\"-I%s\" % i for i in lxml.get_include()])"`

LDFLAGS=-fPIC -Wall -Wpedantic -std=gnu11 -Wno-strict-aliasing -g -O0 \
	-shared -ldl -lm -lz \
	`python2.7-config --ldflags` \
	../../src/libsysrepo.so ../../src/libsysrepo-engine.so -lpthread -lredblack -lev -lprotobuf-c -lyang -Wl,-rpath,/home/equinox/c++/sysrepo/src:

	#cython `python2.7 -c "import lxml; print \" \".join([\"-I%s\" % i for i in lxml.get_include()])"` $<
%.c: %.pyx
	cython -2 $<

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

libsysrepo-cyplugin.so: plugmain.o pysysrepo.o
	gcc $(LDFLAGS) -Wl,-soname,libsysrepo-cyplugin.so -o $@ $^


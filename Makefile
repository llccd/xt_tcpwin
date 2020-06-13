ifneq ($(KERNELRELEASE),)

obj-m += xt_TCPWIN.o

else

KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
CFLAGS = -O3 -Wall
XTABLES_LIBDIR ?= $(shell pkg-config xtables --variable=xtlibdir)

all: modules libxt_TCPWIN.so strip

strip: modules libxt_TCPWIN.so
	strip libxt_TCPWIN.so
	strip --strip-debug xt_TCPWIN.ko

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

lib%.so: lib%.o
	gcc -shared -fPIC -o $@ $^;

lib%.o: lib%.c
	gcc ${CFLAGS} -D_INIT=lib$*_init -fPIC -c -o $@ $<;

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.{o,so}

install: all
	install -m 0644 libxt_TCPWIN.so $(XTABLES_LIBDIR)/
	-rmmod xt_TCPWIN
	insmod xt_TCPWIN.ko
	#install -m 0644 xt_TCPWIN.ko /lib/modules/$(KVERSION)/kernel/net/netfilter/

endif

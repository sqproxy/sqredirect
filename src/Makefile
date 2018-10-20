obj-m := sqproxy_redirect.o

KDIR ?= /lib/modules/`uname -r`/build

ccflags-y := -std=gnu99 -Wno-declaration-after-statement -Wno-unused-variable

default:
	$(MAKE) -C $(KDIR) M=$$PWD modules

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

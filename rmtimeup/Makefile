#
# Makefile for the rfsdelta.ko kernel module for Linux 2.6
# by pts@fazekas.hu at Thu Jan 11 17:33:01 CET 2007
#
# * see also linux/Documentation/kbuild/makefiles.txt
# * see also the Linux Kernel Module Programming Guide
#

# vvv Dat: override with `make KERNEL_VERSION=...'
KERNEL_VERSION = $(shell uname -r)
RMTIMEUP_VERSION = 0.09
PRODUCT = rfsdelta-$(VERSION)

.PHONY: all clean install modules_install

# vvv Dat: used by kbuild ($RMTIMEUP_EXTRA_CFLAGS isn't)
# vvv Dat: -Werror is to catch function prototype mismatches (e.g. vfs_rename)
EXTRA_CFLAGS=-Werror -DUSE_PTS=1 -DUSE_PTS_LINUXKERNEL=1 -DRMTIMEUP_VERSION=\"$(RMTIMEUP_VERSION)\"
#"

# vvv Dat: `-m' is for module
# vvv Dat: the module-name is the 1st .o name in `obj-m'
# vvv Dat: there must be no rmtimeup.c (because of dependency management)
obj-m := rmtimeup.o

rmtimeup-y := mainmod.o ud.o

all:
	make -C /lib/modules/$(KERNEL_VERSION)/build SUBDIRS=$(PWD) modules

clean:
	make -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) clean
	rm -f Module.symvers core DEADJOE a.out

install modules_install:
	make -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) modules_install

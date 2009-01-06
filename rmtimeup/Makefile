#
# Makefile for the rfsdelta.ko kernel module for Linux 2.6
# by pts@fazekas.hu at Thu Jan 11 17:33:01 CET 2007
#
# * see also linux/Documentation/kbuild/makefiles.txt
# * see also the Linux Kernel Module Programming Guide
#

# vvv Dat: override with `make KERNEL_VERSION=...'
KERNEL_VERSION = $(shell uname -r)
RMTIMEUP_VERSION = 0.10
PRODUCT = rfsdelta-$(VERSION)

.PHONY: all clean install modules_install

# Can be overridden in the command line:
# `USE_EXTRA_VFSMNT=1 make'.
# This is needed for the Ubuntu Hardy 2.6.24-22-generic kernel.
USE_EXTRA_VFSMNT ?= 0
USE_EXTRA_VFSMNT_DETECT = 0$(shell >/dev/null grep 'int vfs_unlink()*.*struct vfsmount' /lib/modules/$(KERNEL_VERSION)/build/include/linux/fs.h && echo -n 1)

# This is needed for the Ubuntu Hardy 2.6.24-22-generic kernel.
# Since that kernel doesn't have EXPORT_SYMBOL(kallsyms_lookup_name),
# we have to emulate that using EXPORT_SYMBOL(sprint_symbol).
USE_SPRINT_SYMBOL ?= 0
USE_SPRINT_SYMBOL_DETECT = 0$(shell >/dev/null grep 'int sprint_symbol()*.*char' /lib/modules/$(KERNEL_VERSION)/build/include/linux/kallsyms.h && echo -n 1)

# vvv Dat: used by kbuild ($RMTIMEUP_EXTRA_CFLAGS isn't)
# vvv Dat: -Werror is to catch function prototype mismatches (e.g. vfs_rename)
EXTRA_CFLAGS=-DUSE_EXTRA_VFSMNT=$(USE_EXTRA_VFSMNT) -DUSE_SPRINT_SYMBOL=$(USE_SPRINT_SYMBOL) -Werror -DUSE_PTS=1 -DUSE_PTS_LINUXKERNEL=1 -DRMTIMEUP_VERSION=\"$(RMTIMEUP_VERSION)\"
#"

# vvv Dat: `-m' is for module
# vvv Dat: the module-name is the 1st .o name in `obj-m'
# vvv Dat: there must be no rmtimeup.c (because of dependency management)
obj-m := rmtimeup.o

rmtimeup-y := mainmod.o ud.o

all:
	make -C /lib/modules/$(KERNEL_VERSION)/build SUBDIRS=$(PWD) \
	    USE_EXTRA_VFSMNT=$(USE_EXTRA_VFSMNT_DETECT) \
	    USE_SPRINT_SYMBOL=$(USE_SPRINT_SYMBOL_DETECT) \
	    modules

clean:
	make -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) clean
	rm -f Module.symvers core DEADJOE a.out

install modules_install:
	make -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) modules_install

# SPDX-License-Identifier: GPL-2.0
obj-m += f2fs.o

f2fs-y		:= dir.o file.o inode.o namei.o hash.o super.o inline.o
f2fs-y		+= checkpoint.o gc.o data.o node.o segment.o recovery.o
f2fs-y		+= shrinker.o extent_cache.o sysfs.o verity.o
f2fs-y		+= gogeta.o xatable.o joinable.o

f2fs-$(CONFIG_F2FS_STAT_FS) += debug.o
f2fs-$(CONFIG_F2FS_FS_XATTR) += xattr.o
f2fs-$(CONFIG_F2FS_FS_POSIX_ACL) += acl.o
f2fs-$(CONFIG_F2FS_IO_TRACE) += trace.o

KVERSION = $(shell uname -r)

all:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

gen_compdb:
	@bear make -j$(nproc)

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
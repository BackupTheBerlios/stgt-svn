#
# Makefile for the Linux kernel device drivers.
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -DNETLINK_TGT=17

ifneq ($(KERNELRELEASE),)
obj-m			+= scsi_tgt.o
scsi_tgt-objs		:= scsi_tgt_lib.o scsi_tgt_if.o

else

ifeq ($(KERNELSRC),)
	KERNELSRC ?= /lib/modules/$(shell uname -r)/build
endif

PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(PWD) clean
endif

SUBDIRS := $(shell pwd)

ifeq ($(KERNELSRC),)
	KERNELSRC ?= /lib/modules/$(shell uname -r)/build
endif

all: libs mods

mods:
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(shell pwd)/kernel modules

libs:
	$(MAKE) -C usr

clean:
	$(MAKE) -C usr clean
	$(MAKE) -C $(KERNELSRC) SUBDIRS=$(shell pwd)/kernel clean

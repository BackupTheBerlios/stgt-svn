CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -fPIC -I$(KERNELSRC)/include -I../istgt/include -I../include -I. -D_LARGEFILE64_SOURCE
PROGRAMS = tgtd tgtadm
TGTD_OBJS = tgtd.o tgtif.o mgmt.o target.o scsi.o log.o driver.o util.o

ifneq ($(IBMVIO),)
CFLAGS += -DIBMVIO
TGTD_OBJS += $(addprefix ibmvio/, ibmvio.o)
BD_MMAP=1
endif

ifneq ($(ISCSI),)
CFLAGS += -DISCSI
TGTD_OBJS += $(addprefix iscsi/, istgt.o conn.o param.o session.o iscsid.o target.o chap.o)
LIBS += -lcrypto
BD_AIO=1
endif

ifneq ($(BD_MMAP),)
TGTD_OBJS += bd_mmap.o
endif

ifneq ($(BD_AIO),)
TGTD_OBJS += bd_aio.o
LIBS += -laio
endif

all: $(PROGRAMS)

tgtd: $(TGTD_OBJS)
	$(CC) $^ -g -o $@ $(LIBS)

tgtadm: tgtadm.o
	$(CC) $^ -o $@

clean:
	rm -f *.o $(PROGRAMS)
	$(MAKE) -C iscsi clean
	$(MAKE) -C ibmvio clean

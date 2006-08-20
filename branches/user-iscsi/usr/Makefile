CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -D_LARGEFILE64_SOURCE -I./include -I.
PROGRAMS = tgtd tgtadm
TGTD_OBJS = tgtd.o mgmt.o target.o scsi.o log.o driver.o util.o

CFLAGS += -DISCSI
TGTD_OBJS += $(addprefix iscsi/, istgt.o conn.o param.o session.o iscsid.o target.o chap.o)
LIBS = -lcrypto

all: $(PROGRAMS)

tgtd: $(TGTD_OBJS)
	$(CC) $^ -g -o $@ $(LIBS)

tgtadm: tgtadm.o
	$(CC) $^ -o $@

clean:
	rm -f *.o $(PROGRAMS)
	$(MAKE) -C iscsi clean

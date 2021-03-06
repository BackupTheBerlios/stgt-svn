/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 *
 * Netlink functions are based on open-iscsi code
 * written by Dmitry Yusupov and Alex Aizman.
 *
 * This code is licenced under the GPL.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>

#include <tgt_if.h>
#include "tgtd.h"
#include "dl.h"

#define	NL_BUFSIZE	1024

int __nl_write(int fd, int type, char *data, int len)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) data;
	struct sockaddr_nl daddr;

	memset(nlh, 0, sizeof(*nlh));
	nlh->nlmsg_len = len;
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_pid = getpid();

	memset(&daddr, 0, sizeof(daddr));
	daddr.nl_family = AF_NETLINK;
	daddr.nl_pid = 0;
	daddr.nl_groups = 0;

	return sendto(fd, data, len, 0, (struct sockaddr *) &daddr,
		      sizeof(daddr));
}

int __nl_read(int fd, void *data, int size, int flags)
{
	struct sockaddr_nl saddr;
	socklen_t slen = sizeof(saddr);

	memset(&saddr, 0, sizeof(saddr));
	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = 0; /* not in mcast groups */

	return recvfrom(fd, data, size, flags, (struct sockaddr *) &saddr, &slen);
}

static int nl_read(int fd, char *buf)
{
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	int err;

peek_again:
	err = __nl_read(fd, buf, NLMSG_SPACE(sizeof(*ev)), MSG_PEEK);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto peek_again;
		return err;
	}

	nlh = (struct nlmsghdr *) buf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	dprintf("%d %d %d\n", nlh->nlmsg_type, nlh->nlmsg_len, getpid());

read_again:
	err = __nl_read(fd, buf, nlh->nlmsg_len, 0);
	if (err < 0) {
		eprintf("%d\n", err);
		if (errno == EAGAIN || errno == EINTR)
			goto read_again;
		return err;
	}

	return err;
}

void nl_event_handle(struct driver_info *dinfo, int fd)
{
	struct nlmsghdr *nlh;
	struct tgt_event *ev;
	char rbuf[NL_BUFSIZE];
	int err;
	void (*fn) (char *);

	err = nl_read(fd, rbuf);
	if (err < 0)
		return;

	nlh = (struct nlmsghdr *) rbuf;
	ev = (struct tgt_event *) NLMSG_DATA(nlh);

	dprintf("%d %d\n", getpid(), nlh->nlmsg_type);

	switch (nlh->nlmsg_type) {
	case TGT_KEVENT_TARGET_PASSTHRU:
		fn = dl_event_fn(dinfo, ev->k.tgt_passthru.tid,
				 ev->k.tgt_passthru.typeid);
		if (fn)
			fn(NLMSG_DATA(rbuf));
		else
			eprintf("Cannot handle async event %d\n",
				ev->k.tgt_passthru.tid);
		break;
	default:
		/* kernel module bug */
		eprintf("unknown event %u\n", nlh->nlmsg_type);
		exit(-1);
		break;
	}
}

int nl_cmd_call(int fd, int type, char *sbuf, int slen, char *rbuf, int rlen)
{
	int err;
	struct nlmsghdr *nlh;
	char buf[NL_BUFSIZE];

	err = __nl_write(fd, type, sbuf, slen);
	if (err < 0)
		return err;

	err = nl_read(fd, buf);

	if (rbuf) {
		nlh = (struct nlmsghdr *) buf;
		if (rlen < nlh->nlmsg_len)
			eprintf("Too small rbuf %d %d\n", rlen, nlh->nlmsg_len);
		else
			rlen = nlh->nlmsg_len;

		memcpy(rbuf, nlh, rlen);
	}

	return err;
}

int nl_start(int fd)
{
	int err;
	struct tgt_event *ev;
	char nlmsg[NLMSG_SPACE(sizeof(struct tgt_event))];
	char buf[NL_BUFSIZE];

	err = nl_cmd_call(fd, TGT_UEVENT_START, nlmsg,
			  NLMSG_SPACE(sizeof(struct tgt_event)),
			  buf, NL_BUFSIZE);

	ev = (struct tgt_event *) NLMSG_DATA(buf);
	if (err < 0 || ev->k.event_res.err < 0) {
		eprintf("%d %d\n", err, ev->k.event_res.err);
		return -EINVAL;
	}

	return 0;
}

int nl_init(void)
{
	int fd;

	fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TGT);
	if (fd < 0)
		eprintf("Fail to create the netlink socket %d\n", errno);

	return fd;
}

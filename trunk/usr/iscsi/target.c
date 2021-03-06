/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "iscsid.h"
#include "tgtadm.h"
#include "tgtd.h"
#include "target.h"

static LIST_HEAD(targets_list);

static int netmask_match_v6(struct sockaddr *sa1, struct sockaddr *sa2, uint32_t mbit)
{
	uint16_t mask, a1[8], a2[8];
	int i;

	for (i = 0; i < 8; i++) {
		a1[i] = ntohs(((struct sockaddr_in6 *) sa1)->sin6_addr.s6_addr16[i]);
		a2[i] = ntohs(((struct sockaddr_in6 *) sa2)->sin6_addr.s6_addr16[i]);
	}

	for (i = 0; i < mbit / 16; i++)
		if (a1[i] ^ a2[i])
			return 0;

	if (mbit % 16) {
		mask = ~((1 << (16 - (mbit % 16))) - 1);
		if ((mask & a1[mbit / 16]) ^ (mask & a2[mbit / 16]))
			return 0;
	}

	return 1;
}

static int netmask_match_v4(struct sockaddr *sa1, struct sockaddr *sa2, uint32_t mbit)
{
	uint32_t s1, s2, mask = ~((1 << (32 - mbit)) - 1);

	s1 = htonl(((struct sockaddr_in *) sa1)->sin_addr.s_addr);
	s2 = htonl(((struct sockaddr_in *) sa2)->sin_addr.s_addr);

	if (~mask & s1)
		return 0;

	if (!((mask & s2) ^ (mask & s1)))
		return 1;

	return 0;
}

static int netmask_match(struct sockaddr *sa1, struct sockaddr *sa2, char *buf)
{
	uint32_t mbit;
	uint8_t family = sa1->sa_family;

	mbit = strtoul(buf, NULL, 0);
	if (mbit < 0 ||
	    (family == AF_INET && mbit > 31) ||
	    (family == AF_INET6 && mbit > 127))
		return 0;

	if (family == AF_INET)
		return netmask_match_v4(sa1, sa2, mbit);

	return netmask_match_v6(sa1, sa2, mbit);
}

static int address_match(struct sockaddr *sa1, struct sockaddr *sa2)
{
	if (sa1->sa_family == AF_INET)
		return ((struct sockaddr_in *) sa1)->sin_addr.s_addr ==
			((struct sockaddr_in *) sa2)->sin_addr.s_addr;
	else {
		struct in6_addr *a1, *a2;

		a1 = &((struct sockaddr_in6 *) sa1)->sin6_addr;
		a2 = &((struct sockaddr_in6 *) sa2)->sin6_addr;

		return (a1->s6_addr32[0] == a2->s6_addr32[0] &&
			a1->s6_addr32[1] == a2->s6_addr32[1] &&
			a1->s6_addr32[2] == a2->s6_addr32[2] &&
			a1->s6_addr32[3] == a2->s6_addr32[3]);
	}

	return 0;
}

static int ip_match(int fd, char *address)
{
	struct sockaddr_storage from;
	struct addrinfo hints, *res;
	socklen_t len;
	char *str, *p, *q;
	int err;

	len = sizeof(from);
	err = getpeername(fd, (struct sockaddr *) &from, &len);
	if (err < 0)
		return -EPERM;

	str = p = strdup(address);
	if (!p)
		return -EPERM;

	if (!strcmp(p, "ALL")) {
		err = 0;
		goto out;
	}

	if (*p == '[') {
		p++;
		if (!(q = strchr(p, ']'))) {
			err = -EPERM;
			goto out;
		}
		*(q++) = '\0';
	} else
		q = p;

	if ((q = strchr(q, '/')))
		*(q++) = '\0';

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;

	err = getaddrinfo(p, NULL, &hints, &res);
	if (err < 0) {
		err = -EPERM;
		goto out;
	}

	if (q)
		err = netmask_match(res->ai_addr, (struct sockaddr *) &from, q);
	else
		err = address_match(res->ai_addr, (struct sockaddr *) &from);

	err = !err;

	freeaddrinfo(res);
out:
	free(str);
	return err;
}

int ip_acl(int tid, int fd)
{
	int idx, err;
	char *addr;

	for (idx = 0;; idx++) {
		addr = acl_get(tid, idx);
		if (!addr)
			break;

		err = ip_match(fd, addr);
		if (!err)
			return 0;
	}
	return -EPERM;
}

void target_list_build(struct iscsi_connection *conn, char *addr, char *name)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (name && strcmp(tgt_targetname(target->tid), name))
			continue;

		if (ip_acl(target->tid, conn->fd))
			continue;

		text_key_add(conn, "TargetName", tgt_targetname(target->tid));
		text_key_add(conn, "TargetAddress", addr);
	}
}

struct iscsi_target *target_find_by_name(const char *name)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (!strcmp(tgt_targetname(target->tid), name))
			return target;
	}

	return NULL;
}

struct iscsi_target* target_find_by_id(int tid)
{
	struct iscsi_target *target;

	list_for_each_entry(target, &targets_list, tlist) {
		if (target->tid == tid)
			return target;
	}

	return NULL;
}

int iscsi_target_destroy(int tid)
{
	struct iscsi_target* target;

	if (!(target = target_find_by_id(tid)))
		return -ENOENT;

	if (target->nr_sessions)
		return -EBUSY;

	if (!list_empty(&target->sessions_list)) {
		eprintf("bug still have sessions %d\n", tid);
		exit(-1);
	}

	list_del(&target->tlist);

	free(target);

	return 0;
}

int iscsi_target_create(struct target *t)
{
	int tid = t->tid;
	struct iscsi_target *target;
	struct param default_tgt_session_param[] = {
		{0, 8192},
		{0, 8192},
		{0, DIGEST_NONE},
		{0, DIGEST_NONE},
		{0, 1},
		{0, 1},
		{0, 1},
		{0, 65536},
		{0, 262144},
		{0, 1},
		{0, 1},
		{0, 0},
		{0, 0},
		{0, 0},
		{0, 2},
		{0, 20},
		{0, 2048},
		{0, 2048},
		{0, 1},
	};

	target = malloc(sizeof(*target));
	if (!target)
		return -ENOMEM;

	memset(target, 0, sizeof(*target));

	memcpy(target->session_param, default_tgt_session_param,
	       sizeof(target->session_param));

	INIT_LIST_HEAD(&target->tlist);
	INIT_LIST_HEAD(&target->sessions_list);
	target->tid = tid;
	list_add(&target->tlist, &targets_list);

	return 0;
}

static int iscsi_session_param_update(struct iscsi_target* target, int idx, char *str)
{
	int err;
	unsigned int val;

	err = param_str_to_val(session_keys, idx, str, &val);
	if (err)
		return err;

	err = param_check_val(session_keys, idx, &val);
	if (err < 0)
		return err;

	target->session_param[idx].val = val;

	dprintf("%s %s %u\n", session_keys[idx].name, str, val);

	return 0;
}

int iscsi_target_update(int tid, char *name)
{
	int idx, err = -EINVAL;
	char *str;
	struct iscsi_target* target;

	target = target_find_by_id(tid);
	if (!target)
		return -ENOENT;

	str = name + strlen(name) + 1;

	dprintf("%s:%s\n", name, str);

	idx = param_index_by_name(name, session_keys);
	if (idx >= 0)
		err = iscsi_session_param_update(target, idx, str);
	return err;
}

static int show_iscsi_param(char *buf, struct param *param, int rest)
{
	int i, len, total;
	char value[64];
	struct iscsi_key *keys = session_keys;

	for (i = total = 0; session_keys[i].name; i++) {
		param_val_to_str(keys, i, param[i].val, value);
		len = snprintf(buf, rest, "%s=%s\n", keys[i].name, value);
		buffer_check(buf, total, len, rest);
	}

	return total;
}

static int iscsi_target_show_session(struct iscsi_target* target, uint64_t sid,
				     char *buf, int rest)
{
	int len = 0, total = 0;
	struct iscsi_session *session;

	list_for_each_entry(session, &target->sessions_list, slist) {
		if (session->tsih == sid)
			len = show_iscsi_param(buf, session->session_param, rest);
			buffer_check(buf, total, len, rest);
	}

	return total;
}

int iscsi_target_show(int mode, int tid, uint64_t sid, uint32_t cid, uint64_t lun,
		      char *buf, int rest)
{
	struct iscsi_target* target;
	int len, total = 0;

	target = target_find_by_id(tid);
	if (!target)
		return 0;

	switch (mode) {
	case MODE_TARGET:
		len = show_iscsi_param(buf, target->session_param, rest);
		total += len;
		break;
	case MODE_SESSION:
		len = iscsi_target_show_session(target, sid, buf, rest);
		total += len;
		break;
	default:
		break;
	}

	return total;
}

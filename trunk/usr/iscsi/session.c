/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <errno.h>

#include "iscsid.h"
#include "tgtd.h"
#include "util.h"

static LIST_HEAD(sessions_list);

struct iscsi_session *session_find_name(int tid, const char *iname, uint8_t *isid)
{
	struct iscsi_session *session;
	struct iscsi_target *target;

	target = target_find_by_id(tid);
	if (!target)
		return NULL;

	dprintf("session_find_name: %s %x %x %x %x %x %x\n", iname,
		  isid[0], isid[1], isid[2], isid[3], isid[4], isid[5]);
	list_for_each_entry(session, &target->sessions_list, slist) {
		if (!memcmp(isid, session->isid, sizeof(session->isid)) &&
		    !strcmp(iname, session->initiator))
			return session;
	}

	return NULL;
}

struct iscsi_session *session_lookup(uint64_t nexus_id)
{
	struct iscsi_session *session;
	list_for_each_entry(session, &sessions_list, hlist) {
		if (session->iscsi_nexus_id == nexus_id)
			return session;
	}
	return NULL;
}

static struct iscsi_session *session_lookup_by_tsih(uint16_t tsih)
{
	struct iscsi_session *session;
	list_for_each_entry(session, &sessions_list, hlist) {
		if (session->tsih == tsih)
			return session;
	}
	return NULL;
}

int session_create(struct iscsi_connection *conn)
{
	int err;
	struct iscsi_session *session = NULL;
	static uint16_t tsih, last_tsih = 0;
	struct iscsi_target *target;
	char addr[128];
	uint64_t nexus_id;

	target = target_find_by_id(conn->tid);
	if (!target)
		return -EINVAL;

	for (tsih = last_tsih + 1; tsih != last_tsih; tsih++) {
		if (!tsih)
			continue;
		session = session_lookup_by_tsih(tsih);
		if (!session)
			break;
	}
	if (session)
		return -EINVAL;

	session = zalloc(sizeof(*session));
	if (!session)
		return -ENOMEM;

	session->initiator = strdup(conn->initiator);
	if (!session->initiator) {
		free(session);
		return -ENOMEM;
	}

	session->info = zalloc(1024);
	if (!session->info) {
		free(session->initiator);
		free(session);
		return -ENOMEM;
	}

	memset(addr, 0, sizeof(addr));
	conn->tp->ep_show(conn->fd, addr, sizeof(addr));

	snprintf(session->info, 1024, _TAB3 "Initiator: %s\n"
		 _TAB3 "Connection: %u\n"
		 _TAB4 "%s\n", session->initiator, conn->cid, addr);

	err = it_nexus_create(target->tid, session->info, &nexus_id);
	if (err) {
		free(session->initiator);
		free(session->info);
		free(session);
		return err;
	}

	session->target = target;
	INIT_LIST_HEAD(&session->slist);
	list_add(&session->slist, &target->sessions_list);

	INIT_LIST_HEAD(&session->conn_list);
	INIT_LIST_HEAD(&session->cmd_list);
	INIT_LIST_HEAD(&session->pending_cmd_list);

	memcpy(session->isid, conn->isid, sizeof(session->isid));
	session->tsih = last_tsih = tsih;
	session->iscsi_nexus_id = nexus_id;

	conn_add_to_session(conn, session);

	dprintf("session_create: %#" PRIx64 "\n", sid64(conn->isid, session->tsih));

	list_add(&session->hlist, &sessions_list);
	session->exp_cmd_sn = conn->exp_cmd_sn;

	memcpy(session->session_param, conn->session_param,
	       sizeof(session->session_param));

	return 0;
}

static void session_destroy(struct iscsi_session *session)
{
	if (!list_empty(&session->conn_list)) {
		eprintf("%d conn_list is not null\n", session->tsih);
		return;
	}

	if (session->target) {
		list_del(&session->slist);
/* 		session->target->nr_sessions--; */
	}

	it_nexus_destroy(session->iscsi_nexus_id);

	list_del(&session->hlist);

	free(session->initiator);
	free(session->info);
	free(session);
}

void session_get(struct iscsi_session *session)
{
	session->refcount++;
}

void session_put(struct iscsi_session *session)
{
	if (!--session->refcount)
		session_destroy(session);
}

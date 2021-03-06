/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "iscsid.h"

#define ISCSI_CONN_NEW		1
#define ISCSI_CONN_EXIT		5

void conn_add_to_session(struct connection *conn, struct session *session)
{
	if (!list_empty(&conn->clist)) {
		eprintf("%" PRIx64 " %u\n",
			sid64(session->isid, session->tsih), conn->cid);
		exit(0);
	}

	conn->session = session;
	list_add(&conn->clist, &session->conn_list);
}

struct connection *conn_alloc(void)
{
	struct connection *conn;

	if (!(conn = malloc(sizeof(*conn))))
		return NULL;

	memset(conn, 0, sizeof(*conn));
	conn->state = STATE_FREE;
	param_set_defaults(conn->session_param, session_keys);

	INIT_LIST_HEAD(&conn->clist);

	return conn;
}

void conn_free(struct connection *conn)
{
	list_del(&conn->clist);
	free(conn->initiator);
	free(conn);
}

struct connection *conn_find(struct session *session, uint32_t cid)
{
	struct connection *conn;

	list_for_each_entry(conn, &session->conn_list, clist) {
		if (conn->cid == cid)
			return conn;
	}

	return NULL;
}

void conn_take_fd(struct connection *conn, int fd)
{
	int i, err;
	uint64_t sid = sid64(conn->isid, conn->tsih);

	log_debug("conn_take_fd: %d %u %u %u %" PRIx64,
		  fd, conn->cid, conn->stat_sn, conn->exp_stat_sn, sid);

	conn->session->conn_cnt++;

	err = ki->create_conn(thandle, conn->session->ksid, conn->kcid,
			      &conn->kcid);
	if (err) {
		eprintf("%d %d %u %u %u %" PRIx64,
			fd, err, conn->cid, conn->stat_sn, conn->exp_stat_sn, sid);
		goto out;
	}

	for (i = 0; i < ISCSI_PARAM_ERL + 1; i++) {
		/* FIXME */
		if (i == ISCSI_PARAM_DATADGST_EN || i == ISCSI_PARAM_HDRDGST_EN)
			continue;
		if (ki->set_param(thandle, conn->session->ksid, conn->kcid, i,
				  &conn->session_param[i].val,
				  sizeof(uint32_t), &err) || err) {
			break;
		}
	}

	if (ki->bind_conn(thandle, conn->session->ksid, conn->kcid, fd, 1, &err) || err) {
		eprintf("%d %d %u %u %u %" PRIx64,
			fd, err, conn->cid, conn->stat_sn, conn->exp_stat_sn, sid);
		goto out;
	}

	if (ki->start_conn(thandle, conn->session->ksid, conn->kcid, &err) || err) {
		eprintf("%d %d %u %u %u %" PRIx64,
			fd, err, conn->cid, conn->stat_sn, conn->exp_stat_sn, sid);
		goto out;
	}

out:
	return;
}

void conn_read_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_READ_BHS;
	conn->buffer = (void *)&conn->req.bhs;
	conn->rwsize = BHS_SIZE;
}

void conn_write_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_WRITE_BHS;
	memset(&conn->rsp, 0, sizeof(conn->rsp));
	conn->buffer = (void *)&conn->rsp.bhs;
	conn->rwsize = BHS_SIZE;
}

void conn_free_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_FREE;
	if (conn->req.ahs) {
		free(conn->req.ahs);
		conn->req.ahs = NULL;
	}
	if (conn->rsp.ahs) {
		free(conn->rsp.ahs);
		conn->rsp.ahs = NULL;
	}
	if (conn->rsp.data) {
		free(conn->rsp.data);
		conn->rsp.data = NULL;
	}
}

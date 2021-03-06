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
#include "tgtd.h"

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

	conn = zalloc(sizeof(*conn));
	if (!conn)
		return NULL;

	conn->req_buffer = malloc(INCOMING_BUFSIZE);
	if (!conn->req_buffer) {
		free(conn);
		return NULL;
	}
	conn->rsp_buffer = malloc(INCOMING_BUFSIZE);
	if (!conn->rsp_buffer) {
		free(conn->req_buffer);
		free(conn);
		return NULL;
	}

	conn->state = STATE_FREE;
	param_set_defaults(conn->session_param, session_keys);

	INIT_LIST_HEAD(&conn->send);
	INIT_LIST_HEAD(&conn->clist);

	return conn;
}

void conn_free(struct connection *conn)
{
	list_del(&conn->clist);
	free(conn->req_buffer);
	free(conn->rsp_buffer);
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

int conn_take_fd(struct connection *conn, int fd)
{
	uint64_t sid = sid64(conn->isid, conn->tsih);

	log_debug("conn_take_fd: %d %u %u %u %" PRIx64,
		  fd, conn->cid, conn->stat_sn, conn->exp_stat_sn, sid);

	conn->session->conn_cnt++;

	dprintf("conn_take_fd: %d %u %u %u\n", conn->session->target->tid,
		conn->cid, conn->stat_sn, conn->exp_stat_sn);

	/* FIXME */
	tgt_target_bind(conn->session->target->tid, conn->tsih, 0);

	return 0;
}

void conn_read_pdu(struct connection *conn)
{
	conn->rx_iostate = IOSTATE_READ_BHS;
	conn->buffer = (void *)&conn->req.bhs;
	conn->rwsize = BHS_SIZE;
}

void conn_write_pdu(struct connection *conn, int clear)
{
	conn->tx_iostate = IOSTATE_WRITE_BHS;
	if (clear)
		memset(&conn->rsp, 0, sizeof(conn->rsp));
	conn->buffer = (void *)&conn->rsp.bhs;
	conn->rwsize = BHS_SIZE;
}

void conn_free_pdu(struct connection *conn)
{
	conn->rx_iostate = conn->tx_iostate = IOSTATE_FREE;
/* 	if (conn->req.ahs) { */
/* 		free(conn->req.ahs); */
/* 		conn->req.ahs = NULL; */
/* 	} */
/* 	if (conn->rsp.ahs) { */
/* 		free(conn->rsp.ahs); */
/* 		conn->rsp.ahs = NULL; */
/* 	} */
/* 	if (conn->rsp.data) { */
/* 		free(conn->rsp.data); */
/* 		conn->rsp.data = NULL; */
/* 	} */
}

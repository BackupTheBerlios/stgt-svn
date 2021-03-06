/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSID_H
#define ISCSID_H

#include <sys/types.h>
#include <linux/types.h>

#include "types.h"
#include "iscsi_if.h"
#include "list.h"
#include "param.h"
#include "log.h"

#include <scsi/iscsi_proto.h>

#define ISCSI_NAME_LEN 255
#define ISTGT_NAMESPACE "ISTGT_ABSTRACT_NAMESPACE"

#define DIGEST_ALL	(DIGEST_NONE | DIGEST_CRC32C)
#define DIGEST_NONE		(1 << 0)
#define DIGEST_CRC32C           (1 << 1)

extern uint64_t thandle;
extern int nl_fd;

#define sid64(isid, tsih)					\
({								\
	(uint64_t) isid[0] <<  0 | (uint64_t) isid[1] <<  8 |	\
	(uint64_t) isid[2] << 16 | (uint64_t) isid[3] << 24 |	\
	(uint64_t) isid[4] << 32 | (uint64_t) isid[5] << 40 |	\
	(uint64_t) tsih << 48;					\
})

struct PDU {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	void *data;
	unsigned int datasize;
};

#define KEY_STATE_START		0
#define KEY_STATE_REQUEST	1
#define KEY_STATE_DONE		2

struct session {
	struct list_head slist;
	struct list_head hlist;

	char *initiator;
	struct target *target;
	uint8_t isid[6];
	uint16_t tsih;

	/* workaroud */
	uint32_t ksid;
	uint32_t hostno;

	struct list_head conn_list;
	int conn_cnt;
};

struct connection {
	int state;
	int iostate;
	int fd;

	struct list_head clist;
	struct session *session;

	int tid;
	struct param session_param[ISCSI_PARAM_MAX];

	char *initiator;
	uint8_t isid[6];
	uint16_t tsih;
	uint16_t cid;
	uint16_t pad;
	int session_type;
	int auth_method;

	/* workaroud */
	uint32_t kcid;

	uint32_t stat_sn;
	uint32_t exp_stat_sn;

	uint32_t cmd_sn;
	uint32_t exp_cmd_sn;
	uint32_t max_cmd_sn;

	struct PDU req;
	void *req_buffer;
	struct PDU rsp;
	void *rsp_buffer;
	unsigned char *buffer;
	int rwsize;

	int auth_state;
	union {
		struct {
			int digest_alg;
			int id;
			int challenge_size;
			unsigned char *challenge;
		} chap;
	} auth;
};

#define IOSTATE_FREE		0
#define IOSTATE_READ_BHS	1
#define IOSTATE_READ_AHS_DATA	2
#define IOSTATE_WRITE_BHS	3
#define IOSTATE_WRITE_AHS	4
#define IOSTATE_WRITE_DATA	5

#define STATE_FREE		0
#define STATE_SECURITY		1
#define STATE_SECURITY_AUTH	2
#define STATE_SECURITY_DONE	3
#define STATE_SECURITY_LOGIN	4
#define STATE_SECURITY_FULL	5
#define STATE_LOGIN		6
#define STATE_LOGIN_FULL	7
#define STATE_FULL		8
#define STATE_KERNEL		9
#define STATE_CLOSE		10
#define STATE_EXIT		11

#define AUTH_STATE_START	0
#define AUTH_STATE_CHALLENGE	1

/* don't touch these */
#define AUTH_DIR_INCOMING       0
#define AUTH_DIR_OUTGOING       1

#define SESSION_NORMAL		0
#define SESSION_DISCOVERY	1
#define AUTH_UNKNOWN		-1
#define AUTH_NONE		0
#define AUTH_CHAP		1
#define DIGEST_UNKNOWN		-1

#define BHS_SIZE		48

#define INCOMING_BUFSIZE	8192

struct target {
	struct list_head tlist;

	struct list_head sessions_list;

	int tid;
	char name[ISCSI_NAME_LEN];
	char *alias;

	int max_nr_sessions;
	int nr_sessions;
};

/* chap.c */
extern int cmnd_exec_auth_chap(struct connection *conn);

/* conn.c */
extern struct connection *conn_alloc(void);
extern void conn_free(struct connection *conn);
extern struct connection * conn_find(struct session *session, uint32_t cid);
extern void conn_take_fd(struct connection *conn, int fd);
extern void conn_read_pdu(struct connection *conn);
extern void conn_write_pdu(struct connection *conn);
extern void conn_free_pdu(struct connection *conn);
extern void conn_add_to_session(struct connection *conn, struct session *session);

/* iscsid.c */
extern int iscsi_debug;

extern int cmnd_execute(struct connection *conn);
extern void cmnd_finish(struct connection *conn);
extern char *text_key_find(struct connection *conn, char *searchKey);
extern void text_key_add(struct connection *conn, char *key, char *value);

/* session.c */
extern struct session *session_find_name(int tid, const char *iname, uint8_t *isid);
extern struct session *session_find_id(int tid, uint64_t sid);
extern struct session *session_find_hostno(int hostno);
extern void session_create(struct connection *conn);
extern void session_remove(struct session *session);

/* target.c */
extern int target_find_by_name(const char *name, int *tid);
struct target * target_find_by_id(int tid);
extern void target_list_build(struct connection *, char *, char *);
extern int target_bind(int tid, int hostno);

extern void ipc_event(void);
extern int ipc_init(void);

/* netlink.c */
struct iscsi_kernel_interface {
	int (*set_param) (uint64_t transport_handle, uint32_t sid,
			  uint32_t cid, enum iscsi_param param,
			  void *value, int len, int *retcode);

	int (*create_session) (uint64_t transport_handle,
			       uint32_t initial_cmdsn,
			       uint32_t *out_sid, uint32_t *out_hostno);

	int (*destroy_session) (uint64_t transport_handle, uint32_t sid);

	int (*create_conn) (uint64_t transport_handle,
			    uint32_t sid, uint32_t cid, uint32_t *out_cid);
	int (*destroy_conn) (uint64_t transport_handle, uint32_t sid,
			     uint32_t cid);
	int (*bind_conn) (uint64_t transport_handle, uint32_t sid,
			  uint32_t cid, uint64_t transport_eph,
			  int is_leading, int *retcode);
	int (*start_conn) (uint64_t transport_handle, uint32_t sid,
			   uint32_t cid, int *retcode);

	int (*stop_conn) (uint64_t transport_handle, uint32_t sid,
			  uint32_t cid, int flag);
};

extern int iscsi_nl_init(void);

extern struct iscsi_kernel_interface *ki;

/* param.c */
int param_index_by_name(char *name, struct iscsi_key *keys);

#define log_pdu(x, y)							\
do {									\
} while (0)

#endif	/* ISCSID_H */

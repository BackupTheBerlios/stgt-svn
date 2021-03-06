#ifndef _ISTGT_U_H
#define _ISTGT_U_H

#define VERSION_STRING	"0.4.12"
#define	THIS_NAME		"istgt"

/* The maximum length of 223 bytes in the RFC. */
#define ISCSI_NAME_LEN	256

#define VENDOR_ID_LEN	8
#define SCSI_ID_LEN	24

struct session_info {
	int tid;

	uint64_t sid;
	uint32_t exp_cmd_sn;
	uint32_t max_cmd_sn;
};

#define DIGEST_ALL	(DIGEST_NONE | DIGEST_CRC32C)
#define DIGEST_NONE		(1 << 0)
#define DIGEST_CRC32C           (1 << 1)

struct conn_info {
	int tid;
	uint64_t sid;

	uint32_t cid;
	uint32_t stat_sn;
	uint32_t exp_stat_sn;
	int header_digest;
	int data_digest;
	int fd;
};

enum {
	key_initial_r2t,
	key_immediate_data,
	key_max_connections,
	key_max_recv_data_length,
	key_max_xmit_data_length,
	key_max_burst_length,
	key_first_burst_length,
	key_default_wait_time,
	key_default_retain_time,
	key_max_outstanding_r2t,
	key_data_pdu_inorder,
	key_data_sequence_inorder,
	key_error_recovery_level,
	key_header_digest,
	key_data_digest,
	key_ofmarker,
	key_ifmarker,
	key_ofmarkint,
	key_ifmarkint,
	session_key_last,
};

enum {
	key_queued_cmnds,
	target_key_last,
};

enum {
	key_session,
	key_target,
};

struct iscsi_param_info {
	int tid;
	uint64_t sid;

	uint32_t param_type;
	uint32_t partial;

	uint32_t session_param[session_key_last];
	uint32_t target_param[target_key_last];
};

enum iet_event_state {
	E_CONN_CLOSE,
};

/*
 * msg types
 */
enum {
	IET_ADD_SESSION,
	IET_DEL_SESSION,
	IET_ADD_CONN,
	IET_DEL_CONN,
	IET_ISCSI_PARAM_SET,
	IET_ISCSI_PARAM_GET,
};

struct iet_msg {
	uint32_t msg_type;
	uint32_t result;

	/* user-> kernel */
	union {
		struct session_info sess_info;
		struct conn_info conn_info;
		struct iscsi_param_info param_info;
	} u;

	/* kernel -> user */
	union {
		struct {
			int tid;
			uint64_t sid;
			uint32_t cid;
			uint32_t state;
		} conn_state_change;
	} k;
} __attribute__ ((aligned (sizeof(uint64_t))));

#define	DEFAULT_NR_QUEUED_CMNDS	32
#define	MIN_NR_QUEUED_CMNDS	1
#define	MAX_NR_QUEUED_CMNDS	256

#endif

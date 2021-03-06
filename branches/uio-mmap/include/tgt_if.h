/*
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#ifndef TARGET_FRAMEWORK_IF_H
#define TARGET_FRAMEWORK_IF_H

enum tgt_event_type {
	/* user -> kernel */
	TGT_UEVENT_START,
	TGT_UEVENT_TARGET_CREATE,
	TGT_UEVENT_TARGET_DESTROY,
	TGT_UEVENT_TARGET_PASSTHRU,
	TGT_UEVENT_DEVICE_CREATE,
	TGT_UEVENT_DEVICE_DESTROY,
	TGT_UEVENT_CMD_RES,
	TGT_UEVENT_TASK_MGMT,

	/* kernel -> user */
	TGT_KEVENT_RESPONSE,
	TGT_KEVENT_CMD_REQ,
	TGT_KEVENT_TARGET_PASSTHRU,
	TGT_KEVENT_TASK_MGMT,
	TGT_KEVENT_CMD_DONE,
};

#define	TGT_INVALID_DEV_ID	~0ULL

struct tgt_event {
	/* user-> kernel */
	union {
		struct {
			char type[32];
			int nr_cmds;
		} c_target;
		struct {
			int tid;
		} d_target;
		struct {
			int tid;
			uint32_t len;
		} tgt_passthru;
		struct {
			int tid;
			uint64_t dev_id;
			uint32_t flags;
			char type[32];
			int fd;
		} c_device;
		struct {
			int tid;
			uint64_t dev_id;
		} d_device;
		struct {
			int tid;
			uint64_t dev_id;
			uint64_t cid;
			uint32_t len;
			int result;
			/*
			 * this is screwed for setups with 64 bit kernel
			 * and 32 bit userspace
			 */
			unsigned long uaddr;
			uint64_t offset;
			uint8_t rw;
			uint8_t try_map;
		} cmd_res;
		struct {
			uint64_t rid;
			int func;
			int tid;
			uint64_t sid;
			uint64_t dev_id;
			uint64_t tag;
			int result;
		} task_mgmt;
	} u;

	/* kernel -> user */
	union {
		struct {
			int err;
		} event_res;
		struct {
			int tid;
			uint64_t dev_id;
			uint64_t cid;
			int typeid;
			int fd;
			uint32_t data_len;
		} cmd_req;
		struct {
			int tid;
			uint32_t len;
			int typeid;
		} tgt_passthru;
		struct {
			uint64_t rid;
			int func;
			int tid;
			int typeid;
			uint64_t sid;
			uint64_t dev_id;
			uint64_t tag;
		} task_mgmt;
		struct {
			int tid;
			int typeid;
			unsigned long uaddr;
			uint32_t len;
			int mmapped;
		} cmd_done;
	} k;

	/*
	 * I think a pointer is a unsigned long but this struct
	 * gets passed around from the kernel to userspace and
	 * back again so to handle some ppc64 setups where userspace is
	 * 32 bits but the kernel is 64 we do this odd thing
	 */
	uint64_t data[0];
} __attribute__ ((aligned (sizeof(uint64_t))));

#endif

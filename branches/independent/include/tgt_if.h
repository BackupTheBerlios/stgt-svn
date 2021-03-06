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
	TGT_UEVENT_CMD_RES,

	/* kernel -> user */
	TGT_KEVENT_RESPONSE,
	TGT_KEVENT_CMD_REQ,
	TGT_KEVENT_TARGET_PASSTHRU,
	TGT_KEVENT_CMD_DONE,
};

struct tgt_event {
	int type;
	/* user-> kernel */
	union {
		struct {
			char type[32];
			int nr_cmds;
			int pid;
			int fd;
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
			uint64_t cid;
			uint64_t devid;
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
	} u;

	/* kernel -> user */
	union {
		struct {
			int err;
		} event_res;
		struct {
			int tid;
			uint64_t cid;
			int typeid;
			uint32_t data_len;
		} cmd_req;
		struct {
			int tid;
			uint32_t len;
			int typeid;
		} tgt_passthru;
		struct {
			int tid;
			int typeid;
			uint64_t devid;
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

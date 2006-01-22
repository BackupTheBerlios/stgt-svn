#ifndef __TARGET_DAEMON_H
#define __TARGET_DAEMON_H

#include "log.h"
#include "dl.h"

#define	TGT_INVALID_DEV_ID	~0ULL

extern int nl_fd;

extern int target_thread_create(int *fd);

extern int nl_init(void);
extern void nl_event_handle(struct driver_info *, int fd);
extern int nl_cmd_call(int fd, int type, char *sbuf, int slen, char *rbuf, int rlen);
extern int nl_start(int fd);
extern int __nl_write(int fd, int type, char *data, int len);
extern int __nl_read(int fd, void *data, int size, int flags);

extern int ipc_open(void);
extern void ipc_event_handle(struct driver_info *, int fd);

extern int tgt_device_init(void);
extern int tgt_device_create(int tid, uint64_t lun, int dfd);
extern int tgt_device_destroy(int tid, uint64_t lun);

#endif

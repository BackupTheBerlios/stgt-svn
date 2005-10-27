#ifndef __DL_H
#define __DL_H

extern int dl_init(char *data);
extern void dl_config_load(void);
extern struct pollfd * dl_poll_init(int *nr);

extern void *dl_poll_init_fn(int idx);
extern void *dl_poll_fn(int idx);
extern void *dl_ipc_fn(char *driver);
extern void *dl_event_fn(int tid);

#endif

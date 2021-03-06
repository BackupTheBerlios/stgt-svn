#include <poll.h>

struct tgt_driver {
	const char *name;

	int (*init) (int *);
	int (*poll_init) (struct pollfd *);
	int (*event_handle) (struct pollfd *);

	int (*target_create) (int, char *);
	int (*target_destroy) (int);
	int (*target_bind)(int);

	uint64_t (*scsi_get_lun)(uint8_t *);
	int (*scsi_report_luns)(struct list_head *, uint8_t *, uint8_t *,
				uint8_t *, int *);
	int (*scsi_inquiry)(struct tgt_device *, int, uint8_t *, uint8_t *,
			    uint8_t *, int *);
	int npfd;
	int enable;
	int pfd_index;
};

extern struct tgt_driver *tgt_drivers[];
extern int get_driver_index(char *name);


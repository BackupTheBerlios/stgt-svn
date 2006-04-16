#ifndef __LIBSRP_H__
#define __LIBSRP_H__

#include <linux/list.h>
#include <scsi/scsi_host.h>

struct srp_buf {
	dma_addr_t dma;
	void *buf;
};

struct srp_queue {
	void *pool;
	void *items;
	struct kfifo *queue;
	spinlock_t lock;
};

struct srp_target {
	struct Scsi_Host *shost;
	struct device *dev;

	spinlock_t lock;
	struct list_head cmd_queue;

	size_t srp_iu_size;
	struct srp_queue iu_queue;
	size_t rx_ring_size;
	struct srp_buf **rx_ring;

	/* IB needs tx_ring too */

	void *ldata;
};

struct iu_entry {
	struct srp_target *target;
	struct scsi_cmnd *scmd;

	struct list_head ilist;
	dma_addr_t remote_token;
	unsigned long flags;

	struct srp_buf *sbuf;
};

static inline struct srp_target *host_to_target(struct Scsi_Host *host)
{
	return (struct srp_target *) host->hostdata;
}

extern int srp_target_alloc(struct srp_target *, struct device *, size_t, size_t);
extern void srp_target_free(struct srp_target *);

extern struct iu_entry *srp_iu_get(struct srp_target *);
extern void srp_iu_put(struct iu_entry *);

#endif

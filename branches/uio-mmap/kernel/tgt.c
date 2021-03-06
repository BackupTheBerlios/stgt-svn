/*
 * Core Target Framework code
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/blkdev.h>
#include <linux/file.h>
#include <asm/scatterlist.h>

#include <tgt.h>
#include <tgt_target.h>
#include <tgt_device.h>
#include <tgt_if.h>
#include <tgt_protocol.h>

#include "tgt_priv.h"

MODULE_LICENSE("GPL");

struct task_struct *tgtd_tsk;

static spinlock_t all_targets_lock;
static LIST_HEAD(all_targets);

static spinlock_t target_tmpl_lock;
static LIST_HEAD(target_tmpl_list);

static spinlock_t device_tmpl_lock;
static LIST_HEAD(device_tmpl_list);

static struct target_type_internal *target_template_get(const char *name)
{
	unsigned long flags;
	struct target_type_internal *ti;

	spin_lock_irqsave(&target_tmpl_lock, flags);

	list_for_each_entry(ti, &target_tmpl_list, list)
		if (!strcmp(name, ti->tt->name)) {
			if (!try_module_get(ti->tt->module))
				ti = NULL;
			spin_unlock_irqrestore(&target_tmpl_lock, flags);
			return ti;
		}

	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	return NULL;
}

static void target_template_put(struct tgt_target_template *tt)
{
	module_put(tt->module);
}

int tgt_target_template_register(struct tgt_target_template *tt)
{
	static atomic_t target_type_id = ATOMIC_INIT(0);
	unsigned long flags;
	struct target_type_internal *ti;
	int err;

	ti = kzalloc(sizeof(*ti), GFP_KERNEL);
	if (!ti)
		return -ENOMEM;

	INIT_LIST_HEAD(&ti->list);
	ti->tt = tt;

	ti->proto = tgt_protocol_get(tt->protocol);
	if (!ti->proto) {
		eprintk("Could not find %s protocol\n", tt->protocol);
		kfree(ti);
		return -EINVAL;
	}

	ti->typeid = atomic_add_return(1, &target_type_id);

	err = tgt_sysfs_register_type(ti);
	if (err)
		goto proto_put;

	/* set some defaults if not set */

	/*
	 * If the driver imposes no hard sector transfer limit, start at
	 * machine infinity initially.
	 */
	if (!tt->max_sectors)
		tt->max_sectors = TGT_DEFAULT_MAX_SECTORS;
	/*
	 * assume a 4GB boundary, if not set
	 */
	if (!tt->seg_boundary_mask)
		tt->seg_boundary_mask = 0xffffffff;

	if (!tt->max_segment_size)
		tt->max_segment_size = MAX_SEGMENT_SIZE;

	if (!tt->max_hw_segments)
		tt->max_hw_segments = MAX_HW_SEGMENTS;

	spin_lock_irqsave(&target_tmpl_lock, flags);
	list_add_tail(&ti->list, &target_tmpl_list);
	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	return 0;

proto_put:
	tgt_protocol_put(ti->proto);
	kfree(ti);

	return err;
}
EXPORT_SYMBOL_GPL(tgt_target_template_register);

void tgt_target_template_unregister(struct tgt_target_template *tt)
{
	unsigned long flags;
	struct target_type_internal *ti;

	spin_lock_irqsave(&target_tmpl_lock, flags);

	list_for_each_entry(ti, &target_tmpl_list, list)
		if (ti->tt == tt) {
			list_del(&ti->list);
			goto found;
		}
	ti = NULL;
found:
	spin_unlock_irqrestore(&target_tmpl_lock, flags);

	if (ti) {
		tgt_protocol_put(ti->proto);
		tgt_sysfs_unregister_type(ti);
	}
}
EXPORT_SYMBOL_GPL(tgt_target_template_unregister);

static void tgt_request_fn(struct request_queue *q)
{
	struct tgt_cmd *cmd;
	struct request *rq;

	while ((rq = elv_next_request(q)) != NULL) {
		/* we need to set state or refcount under this lock! */
		cmd = rq->special;
		/*
		 * hit queue depth (command completion will run the
		 * queue again)
		 */
		if (blk_queue_tagged(q) && blk_queue_start_tag(q, rq))
			break;

		spin_unlock_irq(q->queue_lock);

		dprintk("cmd %p tag %d\n", cmd, rq->tag);

		/*
		 * TODO: build a vector of commands and then do the
	 	 * userspace send call
		 */

		/* what should we do on failure here ? */
		if (tgt_uspace_cmd_send(cmd, GFP_ATOMIC) < 0)
			eprintk("command %d failed\n", rq->tag);

		spin_lock_irq(q->queue_lock);
	}
}

static void tgt_queue_destroy(struct request_queue *q)
{
	blk_cleanup_queue(q);
}

static int tgt_queue_create(struct tgt_protocol *proto, int depth,
			    struct request_queue **queue)
{
	struct request_queue *q;
	int err = -ENOMEM;

	*queue = q = blk_init_queue(tgt_request_fn, NULL);
	if (!q)
		return -ENOMEM;

	elevator_exit(q->elevator);
	err = elevator_init(q, "noop");
	if (err)
		goto out;

	/* who should set this limit ? */
	err = blk_queue_init_tags(q, depth, NULL);
	if (err)
		goto out;

	return 0;
out:
	tgt_queue_destroy(q);
	return err;
}

struct tgt_target *target_find(int tid)
{
	struct tgt_target *target;

	spin_lock(&all_targets_lock);
	list_for_each_entry(target, &all_targets, tlist) {
		if (target->tid == tid)
			goto found;
	}
	target = NULL;
found:
	spin_unlock(&all_targets_lock);

	return target;
}

struct tgt_target *tgt_target_create(char *target_type, int queued_cmds)
{
	char name[16];
	static int target_id;
	struct tgt_target *target;
	struct target_type_internal *ti;

	target = kzalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return NULL;

	ti = target_template_get(target_type);
	if (!ti)
		goto free_target;

	target->state = TGT_CREATED;
	target->tt = ti->tt;
	target->proto = ti->proto;
	target->typeid = ti->typeid;
	target->tid = target_id++;
	spin_lock_init(&target->lock);

	INIT_LIST_HEAD(&target->session_list);
	INIT_LIST_HEAD(&target->device_list);

	target->queued_cmds = queued_cmds;

	snprintf(name, sizeof(name), "tgtd%d", target->tid);
	target->twq = create_workqueue(name);
	if (!target->twq)
		goto put_template;

	target->tt_data = kzalloc(target->tt->priv_data_size, GFP_KERNEL);
	if (!target->tt_data)
		goto free_workqueue;

	if (target->tt->target_create)
		if (target->tt->target_create(target))
			goto free_priv_tt_data;

	if (tgt_queue_create(target->proto, queued_cmds ? : TGT_QUEUE_DEPTH,
			     &target->q))
		goto tt_destroy;

	if (tgt_sysfs_register_target(target))
		goto queue_destroy;

	spin_lock(&all_targets_lock);
	list_add(&target->tlist, &all_targets);
	spin_unlock(&all_targets_lock);
	return target;

queue_destroy:
	tgt_queue_destroy(target->q);
tt_destroy:
	if (target->tt->target_destroy)
		target->tt->target_destroy(target);
free_priv_tt_data:
	kfree(target->tt_data);
free_workqueue:
	destroy_workqueue(target->twq);
put_template:
	target_template_put(target->tt);
free_target:
	kfree(target);
	return NULL;
}
EXPORT_SYMBOL_GPL(tgt_target_create);

int tgt_target_destroy(struct tgt_target *target)
{
	unsigned long flags;

	dprintk("%p\n", target);

	spin_lock_irqsave(&target->lock, flags);
	if (!list_empty(&target->device_list)) {
		spin_unlock_irqrestore(&target->lock, flags);
		return -EBUSY;
	}
	/* userspace and maybe a hotunplug are racing (TODO refcounts) */
	if (target->state == TGT_DESTROYED)
		return -ENODEV;
	target->state = TGT_DESTROYED;
	spin_unlock_irqrestore(&target->lock, flags);

	spin_lock(&all_targets_lock);
	list_del(&target->tlist);
	spin_unlock(&all_targets_lock);

	if (target->tt->target_destroy)
		target->tt->target_destroy(target);

	destroy_workqueue(target->twq);
	tgt_queue_destroy(target->q);
	target_template_put(target->tt);
	tgt_sysfs_unregister_target(target);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_target_destroy);

static void tgt_session_op_init(struct tgt_session *session,
				void (*func)(void *),
				tgt_session_done_t *done, void *arg)
{
	session->done = done;
	session->arg = arg;
	INIT_WORK(&session->work, func, session);
	queue_work(session->target->twq, &session->work);
}

static void tgt_session_async_create(void *data)
{
	struct tgt_session *session = (struct tgt_session *) data;
	struct tgt_target *target = session->target;
	struct tgt_protocol *proto = session->target->proto;
	unsigned long flags;
	int err = 0;

	session->cmd_pool = mempool_create(TGT_MAX_CMD, mempool_alloc_slab,
					   mempool_free_slab, proto->cmd_cache);
	if (!session->cmd_pool)
		err = -ENOMEM;

	if (!err) {
		spin_lock_irqsave(&target->lock, flags);
		list_add(&session->slist, &target->session_list);
		spin_unlock_irqrestore(&target->lock, flags);
	}

	session->done(session->arg, err ? NULL : session);
	if (err)
		kfree(session);
}

int tgt_session_create(struct tgt_target *target, tgt_session_done_t *done,
		       void *arg)
{
	struct tgt_session *session;

	BUG_ON(!done);
	session = kzalloc(sizeof(*session), GFP_ATOMIC);
	if (!session)
		return -ENOMEM;
	session->target = target;
	INIT_LIST_HEAD(&session->slist);

	tgt_session_op_init(session, tgt_session_async_create, done, arg);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_session_create);

static void tgt_session_async_destroy(void *data)
{
	struct tgt_session *session = (struct tgt_session *) data;
	struct tgt_target *target = session->target;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	list_del(&session->slist);
	spin_unlock_irqrestore(&target->lock, flags);

	if (session->done)
		session->done(session->arg, NULL);

	mempool_destroy(session->cmd_pool);
	kfree(session);
}

int tgt_session_destroy(struct tgt_session *session,
			tgt_session_done_t *done, void *arg)
{
	tgt_session_op_init(session, tgt_session_async_destroy,
			    done, arg);
	return 0;
}
EXPORT_SYMBOL_GPL(tgt_session_destroy);

/*
 * TODO: use a hash or any better alg/ds
 */
static struct tgt_device *
tgt_device_find_nolock(struct tgt_target *target, uint64_t dev_id)
{
	struct tgt_device *device;

	list_for_each_entry(device, &target->device_list, dlist)
		if (device->dev_id == dev_id)
			return device;

	return NULL;
}

static struct tgt_device *tgt_device_find(struct tgt_target *target, uint64_t dev_id)
{
	static struct tgt_device *device;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	spin_unlock_irqrestore(&target->lock, flags);

	return device;
}

struct tgt_device *tgt_device_get(struct tgt_target *target, uint64_t dev_id)
{
	static struct tgt_device *device;
	unsigned long flags;

	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	if (device) {
		if (test_bit(TGT_DEV_DEL, &device->state))
			device = NULL;
		else
			class_device_get(&device->cdev);
	}
	spin_unlock_irqrestore(&target->lock, flags);

	return device;
}
EXPORT_SYMBOL_GPL(tgt_device_get);

void tgt_device_put(struct tgt_device *device)
{
	class_device_put(&device->cdev);
}
EXPORT_SYMBOL_GPL(tgt_device_put);

#define min_not_zero(l, r) (l == 0) ? r : ((r == 0) ? l : min(l, r))

static int tgt_device_queue_setup(struct tgt_device *device)
{
	struct io_restrictions *limits = &device->limits;
	struct tgt_target_template *tt = device->target->tt;
	struct request_queue *q = device->q;

	device->q = q;

	blk_queue_max_sectors(q, min_not_zero(tt->max_sectors,
					limits->max_sectors));
	blk_queue_max_phys_segments(q, min_not_zero(limits->max_phys_segments,
					(unsigned short)TGT_MAX_PHYS_SEGMENTS));
	blk_queue_max_hw_segments(q, min_not_zero(tt->max_hw_segments,
					limits->max_hw_segments));
	blk_queue_max_segment_size(q, min_not_zero(tt->max_segment_size,
					limits->max_segment_size));
	blk_queue_segment_boundary(q, min_not_zero(tt->seg_boundary_mask,
					limits->seg_boundary_mask));
	if (!tt->use_clustering || !device->use_clustering)
		clear_bit(QUEUE_FLAG_CLUSTER, &q->queue_flags);

	dprintk("max_sectors %u\n", q->max_sectors);
	dprintk("max_phys_segments %u\n", q->max_phys_segments);
	dprintk("max_hw_segments %u\n", q->max_hw_segments);
	dprintk("max_segment_size %u\n", q->max_segment_size);
	dprintk("seg_boundary_mask %lx\n", q->seg_boundary_mask);
	if (test_bit(QUEUE_FLAG_CLUSTER, &q->queue_flags))
		dprintk("clustering set\n");
	else
		dprintk("clustering not set\n");

	return 0;
}

int tgt_device_create(int tid, uint64_t dev_id, char *device_type,
		      int fd, unsigned long dflags)
{
	struct tgt_target *target;
	struct tgt_device *device;
	unsigned long flags;
	struct inode *inode;

	dprintk("tid %d dev_id %" PRIu64 " type %s fd %d\n",
		tid, dev_id, device_type, fd);

	target = target_find(tid);
	if (!target)
		return -EINVAL;

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		return -ENOMEM;

	device->dev_id = dev_id;
	device->target = target;
	device->fd = fd;

	device->file = fget(fd);
	if (!device->file) {
		eprintk("Could not get fd %d\n", fd);
		goto free_device;
	}

	/* TODO: kill me */
	inode = device->file->f_dentry->d_inode;
	if (S_ISREG(inode->i_mode))
		;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;

	device->use_clustering = 1;
	device->size = inode->i_size;

	if (tgt_queue_create(target->proto, TGT_QUEUE_DEPTH, &device->q))
		goto put_fd;
	tgt_device_queue_setup(device);

	if (tgt_sysfs_register_device(device))
		goto queue_destroy;

	spin_lock_irqsave(&target->lock, flags);
	list_add(&device->dlist, &target->device_list);
	spin_unlock_irqrestore(&target->lock, flags);

	return 0;

queue_destroy:
	tgt_queue_destroy(device->q);
put_fd:
	fput(device->file);
free_device:
	kfree(device);
	return -EINVAL;
}

void tgt_device_free(struct tgt_device *device)
{
	struct tgt_target *target = device->target;
	unsigned long flags;

	dprintk("%d %lld\n", target->tid, (unsigned long long) device->dev_id);

	spin_lock_irqsave(&target->lock, flags);
	list_del(&device->dlist);
	spin_unlock_irqrestore(&target->lock, flags);

	tgt_queue_destroy(device->q);
	fput(device->file);

	kfree(device);
}

int tgt_device_destroy(int tid, uint64_t dev_id)
{
	struct tgt_device *device;
	struct tgt_target *target;
	unsigned long flags;
	int err = 0;

	target = target_find(tid);
	if (!target)
		return -ENOENT;

	/*
	 * We cannot delete the device from the list because
	 * uspace_cmd_done would use it later.
	 */
	spin_lock_irqsave(&target->lock, flags);
	device = tgt_device_find_nolock(target, dev_id);
	if (device)
		err = test_and_set_bit(TGT_DEV_DEL, &device->state);
	spin_unlock_irqrestore(&target->lock, flags);

	if (!device)
		return -ENOENT;

	if (err) {
		eprintk("the device is being removed %d %lld\n",
			tid, (unsigned long long) dev_id);
		return -EBUSY;
	} else {
		/* TODO: revoke commands in the devece queue here. */
		tgt_sysfs_unregister_device(device);
		return 0;
	}
}

static void tgt_unmap_user_pages(struct tgt_cmd *cmd)
{
	struct page *page;
	int i;

	for (i = 0; i < cmd->sg_count; i++) {
		page = cmd->pages[i];
		if(!page)
			break;
		if (test_bit(TGT_CMD_RW, &cmd->flags))
			set_page_dirty_lock(page);
		page_cache_release(page);
	}
	kfree(cmd->pages);
}

static void __tgt_cmd_destroy(void *data)
{
	struct tgt_cmd *cmd = data;
	struct request *rq = cmd->rq;
	struct request_queue *q = rq->q;
	unsigned long flags;

	dprintk("tag %d\n", rq->tag);

	tgt_unmap_user_pages(cmd);
	kfree(cmd->sg);
	tgt_uspace_cmd_done_send(cmd, GFP_KERNEL);

	spin_lock_irqsave(q->queue_lock, flags);
	if (blk_rq_tagged(rq))
		blk_queue_end_tag(q, rq);
	end_that_request_last(rq);
	spin_unlock_irqrestore(q->queue_lock, flags);

	if (cmd->device)
		tgt_device_put(cmd->device);

	mempool_free(cmd, cmd->session->cmd_pool);

	blk_run_queue(q);
}

static void tgt_cmd_destroy(struct tgt_cmd *cmd)
{
	dprintk("cmd %p\n", cmd);

	/*
	 * Goose the queue incase we are blocked on a queue depth
	 * limit or resource problem.
	 *
	 * This is run from a interrpt handler normally so we queue
	 * the work
	 */
	INIT_WORK(&cmd->work, __tgt_cmd_destroy, cmd);
	queue_work(cmd->session->target->twq, &cmd->work);
}

void tgt_transfer_response(void *data)
{
	struct tgt_cmd *cmd = data;
	struct tgt_target *target = cmd->session->target;
	int err;

	dprintk("cmd %p\n", cmd);

	cmd->done = tgt_cmd_destroy;
	err = target->tt->transfer_response(cmd);
	switch (err) {
	case TGT_CMD_XMIT_FAILED:
	case TGT_CMD_XMIT_REQUEUE:
		/*
		 * TODO add a real queue to avoid re-orders and starvation
		 * for now just reschedule.
		 */
		INIT_WORK(&cmd->work, tgt_transfer_response, cmd);
		queue_delayed_work(cmd->session->target->twq, &cmd->work,
				   10 * HZ);
		break;
	}
}
EXPORT_SYMBOL_GPL(tgt_transfer_response);

static int tgt_cmd_queue(struct tgt_cmd *cmd, gfp_t gfp_mask)
{
	int write = (cmd->data_dir == DMA_TO_DEVICE);
	struct request_queue *q;
	struct request *rq;

	if (cmd->device)
		q = cmd->device->q;
	else
		q = cmd->session->target->q;

	rq = blk_get_request(q, write, gfp_mask);
	if (!rq)
		return -ENOMEM;

	cmd->rq = rq;
	rq->special = cmd;
	rq->flags |= REQ_SPECIAL | REQ_SOFTBARRIER | REQ_NOMERGE | REQ_BLOCK_PC;
	elv_add_request(q, rq, ELEVATOR_INSERT_BACK, 1);
	return 0;
}

struct tgt_cmd *
tgt_cmd_create(struct tgt_session *session, void *tgt_priv, uint8_t *cb,
	       uint32_t data_len, enum dma_data_direction data_dir,
	       uint8_t *dev_buf, int dev_buf_size, int flags)
{
	struct tgt_cmd *cmd;
	int err;

	cmd = mempool_alloc(session->cmd_pool, GFP_ATOMIC);
	if (!cmd) {
		eprintk("Could not allocate tgt_cmd for %p\n", session);
		return NULL;
	}
	memset(cmd, 0, sizeof(*cmd));
	session->target->proto->cmd_create(cmd, cb, data_len, data_dir,
					   dev_buf, dev_buf_size, flags);

	cmd->device = tgt_device_get(session->target, cmd->dev_id);
	cmd->session = session;
	cmd->private = tgt_priv;
	cmd->done = tgt_cmd_destroy;
	atomic_set(&cmd->state, TGT_CMD_CREATED);

	dprintk("%p %p\n", session, cmd);

	err = tgt_cmd_queue(cmd, GFP_ATOMIC);
	if (err) {
		mempool_free(cmd, cmd->session->cmd_pool);
		return NULL;
	}

	return cmd;
}
EXPORT_SYMBOL_GPL(tgt_cmd_create);

static void tgt_write_data_transfer_done(struct tgt_cmd *cmd)
{
	/*
	 * TODO check for errors and add state checking. we may have
	 * to internally queue for the target driver
	 */
	tgt_transfer_response(cmd);
}

/*
 * we should jsut pass the cmd pointer between userspace and the kernel
 * as a handle like open-iscsi
 */
static struct tgt_cmd *find_cmd_by_id(int tid, uint64_t dev_id, uint64_t cid)
{
	struct tgt_target *target;
	struct tgt_device *device;
	struct request_queue *q;
	struct request *rq;

	dprintk("%d %llu %llu\n", tid, (unsigned long long) dev_id,
		(unsigned long long) cid);

	target = target_find(tid);
	if (!target) {
		eprintk("Could not find target %d\n", tid);
		return NULL;
	}

	if (dev_id == TGT_INVALID_DEV_ID)
		q = target->q;
	else {
		device = tgt_device_find(target, dev_id);
		if (!device) {
			eprintk("Could not find device %llu\n",
				(unsigned long long) dev_id);
			return NULL;
		}
		q = device->q;
	}

	rq = blk_queue_find_tag(q, cid);
	if (rq)
		return rq->special;

	eprintk("Could not find rq for cid %llu\n", (unsigned long long) cid);
	return NULL;
}

#define pgcnt(size, offset)	((((size) + ((offset) & ~PAGE_CACHE_MASK)) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT)

static int tgt_map_user_pages(int rw, struct tgt_cmd *cmd)
{
	int i, err = -EIO, cnt;
	struct page *page, **pages;
	uint64_t poffset = cmd->offset & ~PAGE_MASK;
	uint32_t size, rest = cmd->bufflen;

	cnt = pgcnt(cmd->bufflen, cmd->offset);
	pages = kzalloc(cnt * sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;
	cmd->pages = pages;

	cmd->sg = kmalloc(cnt * sizeof(struct scatterlist), GFP_KERNEL);
	if (!cmd->sg)
		goto release_pages;
	cmd->sg_count = cnt;

	dprintk("cmd %p addr %lx cnt %d\n", cmd, cmd->uaddr, cnt);

	down_read(&tgtd_tsk->mm->mmap_sem);
	err = get_user_pages(tgtd_tsk, tgtd_tsk->mm, cmd->uaddr, cnt,
			     rw == WRITE, 0, pages, NULL);
	up_read(&tgtd_tsk->mm->mmap_sem);

	if (err < cnt) {
		err = -EIO;
		goto free_sg;
	}

	/*
	 * We have a request_queue and we have a the SGIO scatterlist stuff in
	 * scsi-misc so we can use those functions to make us a request with
	 * a proper scatterlist by using block layer funciotns ?????
	 *
	 * do a:
	 * scsi_req_map_sg(cmd->rq, tmp_sg, cnt, orig_size, GFP_KERNEL);
	 * blk_rq_map_sg(cmd->device->q or cmd->target->q, cmd->rq, cmd->sg);
	 */
	for (i = 0; i < cnt; i++) {
		size = min_t(uint32_t, rest, PAGE_SIZE - poffset);

		cmd->sg[i].page = pages[i];
		cmd->sg[i].offset = poffset;
		cmd->sg[i].length = size;

		poffset = 0;
		rest -= size;
	}

	return 0;

free_sg:
	kfree(cmd->sg);
release_pages:
	for (i = 0; i < cnt; i++) {
		page = pages[i];
		if(!page)
			break;
		if (!err && rw == WRITE)
			set_page_dirty_lock(page);
		page_cache_release(page);
	}
	kfree(pages);

	return err;
}

int uspace_cmd_done(int tid, uint64_t dev_id, uint64_t cid,
		    int result, uint32_t len, uint64_t offset,
		    unsigned long uaddr, uint8_t rw, uint8_t try_map)
{
	struct tgt_target *target;
	struct tgt_cmd *cmd;

	cmd = find_cmd_by_id(tid, dev_id, cid);
	if (!cmd) {
		eprintk("Could not find command %llu\n",
			(unsigned long long) cid);
		return -EINVAL;
	}

	dprintk("cmd %p tag %d result %d len %d bufflen %u\n",
		cmd, cmd->rq->tag, result, len, cmd->bufflen);

	cmd->uaddr = uaddr;
	cmd->result = result;
	cmd->offset = offset;
	if (len)
		cmd->bufflen = len;
	if (rw == WRITE)
		__set_bit(TGT_CMD_RW, &cmd->flags);
	if (try_map)
		__set_bit(TGT_CMD_MAPPED, &cmd->flags);

	target = cmd->session->target;
/* 	target->proto->uspace_cmd_complete(cmd); */

	if (cmd->bufflen) {
		if (tgt_map_user_pages(rw, cmd))
			return -EIO;
		if (cmd->data_dir == DMA_TO_DEVICE) {
			cmd->done = tgt_write_data_transfer_done;
			/*
			 * TODO handle errors and possibly requeue for the
			 * target driver
			 */
			target->tt->transfer_write_data(cmd);
			return 0;
		}
	}

	tgt_transfer_response(cmd);
	return 0;
}

/* Should we create proto->task_mgmt ? */

struct tgt_task_mgmt_info {
	struct tgt_target *target;
	struct work_struct work;
	uint64_t rid;
	int res;
};

static void tgt_task_mgmt_done(void *data)
{
	struct tgt_task_mgmt_info *mi = (struct tgt_task_mgmt_info *) data;
	struct tgt_target *target = mi->target;

	target->tt->task_mgmt_done(mi->rid, mi->res);
	kfree(mi);
}

int tgt_task_mgmt(uint64_t rid, int func, int tid, uint64_t sid,
		  uint64_t dev_id, uint64_t tag, int res)
{
	int err = 0;
	struct tgt_target *target = target_find(tid);
	struct tgt_task_mgmt_info *mi;

	dprintk("%llu %d %d %llu %llu %llu %d\n",
		rid, func, tid, sid, dev_id, tag, res);

	if (target && target->tt->task_mgmt_done) {
		mi = kzalloc(sizeof(*mi), GFP_KERNEL);
		if (!mi)
			return -ENOMEM;

		mi->target = target;
		mi->rid = rid;
		mi->res = res;
		INIT_WORK(&mi->work, tgt_task_mgmt_done, mi);
		queue_work(target->twq, &mi->work);
	} else
		err = -EINVAL;

	return err;
}

static void __exit tgt_exit(void)
{
	tgt_nl_exit();
	tgt_sysfs_exit();
}

static int __init tgt_init(void)
{
	int err = -ENOMEM;

	spin_lock_init(&all_targets_lock);
	spin_lock_init(&target_tmpl_lock);
	spin_lock_init(&device_tmpl_lock);

	tgt_protocol_init();

	err = tgt_sysfs_init();
	if (err)
		return err;

	err = tgt_nl_init();
	if (err)
		goto out;

	return 0;
out:
	tgt_sysfs_exit();
	return err;
}

module_init(tgt_init);
module_exit(tgt_exit);

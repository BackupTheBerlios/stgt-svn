/*
 * virtual scsi disk functions
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/writeback.h>

#include <scsi/scsi.h>

#include <tgt.h>
#include <tgt_target.h>
#include <tgt_device.h>
#include <tgt_scsi.h>

static int tgt_vsd_create(struct tgt_device *device)
{
	struct inode *inode;

	inode = device->file->f_dentry->d_inode;
	if (S_ISREG(inode->i_mode))
		;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else
		return -EINVAL;

	device->use_clustering = 1;
	device->size = inode->i_size;
	dprintk("%d %llu\n", device->fd, inode->i_size >> 9);

	return 0;
}

/*
 * is this device specific or common? Should it be moved to the protocol.
 */
static void tgt_vsd_prep(struct tgt_cmd *cmd)
{
	struct scsi_tgt_cmd *scmd = tgt_cmd_to_scsi(cmd);
	uint8_t *scb = scmd->scb;
	uint64_t off = 0;

	/*
	 * set bufflen and offset
	 */
	switch (scb[0]) {
	case READ_6:
	case WRITE_6:
		off = ((scb[1] & 0x1f) << 16) + (scb[2] << 8) + scb[3];
		break;
	case READ_10:
	case WRITE_10:
	case WRITE_VERIFY:
		off = be32_to_cpu(*(uint32_t *) &scb[2]);
		break;
	case READ_16:
	case WRITE_16:
		off = be64_to_cpu(*(uint64_t *) &scb[2]);
		break;
	default:
		break;
	}

	off <<= 9;

	cmd->offset = off;
}

static void __tgt_vsd_execute(void *data)
{
	struct tgt_cmd *cmd = data;
	int err;

	err = tgt_uspace_cmd_send(cmd, GFP_KERNEL);
	if (err >= 0)
		return;

	/* TODO if -ENOMEM return QUEUEFULL or BUSY ??? */
	scsi_tgt_sense_data_build(cmd, HARDWARE_ERROR, 0, 0);
}

static int tgt_vsd_execute(struct tgt_cmd *cmd)
{
	/*
	 * TODO: this module needs to do async non blocking io or create
	 * its own threads
	 */
	INIT_WORK(&cmd->work, __tgt_vsd_execute, cmd);
	queue_work(cmd->session->target->twq, &cmd->work);
	return TGT_CMD_KERN_QUEUED;
}

static struct tgt_device_template tgt_vsd = {
	.name = "tgt_vsd",
	.module = THIS_MODULE,
	.create = tgt_vsd_create,
	.execute_cmd = tgt_vsd_execute,
	.prep_cmd = tgt_vsd_prep,
};

static int __init tgt_vsd_init(void)
{
	return tgt_device_template_register(&tgt_vsd);
}

static void __exit tgt_vsd_exit(void)
{
	tgt_device_template_unregister(&tgt_vsd);
}

module_init(tgt_vsd_init);
module_exit(tgt_vsd_exit);
MODULE_LICENSE("GPL");

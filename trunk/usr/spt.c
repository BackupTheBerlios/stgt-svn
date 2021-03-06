/*
 * SCSI pass through
 *
 * Copyright (C) 2006-2007 FUJITA Tomonori <tomof@acm.org>
 * Copyright (C) 2006-2007 Mike Christie <michaelc@cs.wisc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <linux/types.h>
#include <scsi/sg.h>

#include "list.h"
#include "util.h"
#include "tgtd.h"
#include "target.h"
#include "scsi.h"
#include "spc.h"

extern int spt_sg_open(struct tgt_device *dev, char *path, int *fd, uint64_t *size);
extern int spt_sg_perform(struct scsi_cmd *cmd);

static void spt_sg_close(struct tgt_device *dev)
{
	tgt_event_del(dev->fd);
	close(dev->fd);
}

static int spt_sg_cmd_done(int do_munmap, int do_free, uint64_t uaddr, int len)
{
	return 0;
}

struct backingstore_template sg_bst = {
	.bs_open		= spt_sg_open,
	.bs_close		= spt_sg_close,
	.bs_cmd_done		= spt_sg_cmd_done,
};

static int spt_cmd_perform(int host_no, struct scsi_cmd *cmd)
{
	int ret;
	struct device_type_operations *ops;

	if (!cmd->dev) {
		ops = cmd->c_target->dev_type_template.ops;
		return ops[cmd->scb[0]].cmd_perform(host_no, cmd);
	}

	ret = spt_sg_perform(cmd);
	if (ret) {
		cmd->len = 0;
		sense_data_build(cmd, ILLEGAL_REQUEST, 0x25, 0);
		return SAM_STAT_CHECK_CONDITION;
	} else
		return SAM_STAT_GOOD;
}

struct device_type_template spt_template = {
	.name	= "passthrough",
	.ops	= {
		[0x00 ... 0x9f] = {spt_cmd_perform,},

		/* 0xA0 */
		{spc_report_luns,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},

		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},
		{spt_cmd_perform,},

		[0xb0 ... 0xff] = {spt_cmd_perform},
	}
};

/*
 * Target Netlink Framework code
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <linux/netlink.h>
#include <net/tcp.h>

#include <tgt.h>
#include <tgt_target.h>
#include <tgt_if.h>
#include <tgt_protocol.h>
#include "tgt_priv.h"

static int tgtd_pid;
static struct sock *nls;
static void *zero_page;

static int send_event_res(uint16_t type, struct tgt_event *p,
			  void *data, int dlen, gfp_t flags, uint32_t pid)
{
	struct tgt_event *ev;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	uint32_t len;

	len = NLMSG_SPACE(sizeof(*ev) + dlen);
	skb = alloc_skb(len, flags);
	if (!skb)
		return -ENOMEM;

	nlh = __nlmsg_put(skb, pid, 0, type, len - sizeof(*nlh), 0);

	ev = NLMSG_DATA(nlh);
	memcpy(ev, p, sizeof(*ev));
	if (dlen)
		memcpy(ev->data, data, dlen);

	return netlink_unicast(nls, skb, pid, 0);
}

int tgt_msg_send(struct tgt_target *target, void *data, int dlen, gfp_t flags)
{
	struct tgt_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.k.tgt_passthru.tid = target->tid;
	ev.k.tgt_passthru.typeid = target->typeid;
	ev.k.tgt_passthru.len = dlen;

	return send_event_res(TGT_KEVENT_TARGET_PASSTHRU,
			      &ev, data, dlen, flags, tgtd_pid);
}
EXPORT_SYMBOL_GPL(tgt_msg_send);

static int event_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;
	struct tgt_event *ev = NLMSG_DATA(nlh);
	struct tgt_target *target;

	dprintk("%d %d %d\n", nlh->nlmsg_type,
		nlh->nlmsg_pid, current->pid);

	switch (nlh->nlmsg_type) {
	case TGT_UEVENT_START:
		if (!tgtd_pid) {
			tgtd_pid = NETLINK_CREDS(skb)->pid;
			eprintk("target core start %d\n", tgtd_pid);
		} else
			eprintk("target core already started %d\n",
				NETLINK_CREDS(skb)->pid);

		break;
	case TGT_UEVENT_TARGET_CREATE:
		target = tgt_target_create(ev->u.c_target.type,
					   ev->u.c_target.nr_cmds,
					   ev->u.c_target.pid,
					   ev->u.c_target.fd);
		if (target) {
			err = target->tid;
			dprintk("%d %d %d\n", target->tid,
				target->tsk->pid, err);
		} else
			err = -EINVAL;
		break;
	case TGT_UEVENT_TARGET_DESTROY:
		target = target_find(ev->u.d_target.tid);
		if (target)
			err = tgt_target_destroy(target);
		else
			err = -EINVAL;
		break;
	case TGT_UEVENT_TARGET_PASSTHRU:
		target = target_find(ev->u.tgt_passthru.tid);
		if (!target || !target->tt->msg_recv) {
			dprintk("Could not find target %d for passthru\n",
				ev->u.tgt_passthru.tid);
			err = -EINVAL;
			break;
		}

		err = target->tt->msg_recv(target, ev->u.tgt_passthru.len,
					   ev->data);
		break;
	case TGT_UEVENT_CMD_RES:
		err = uspace_cmd_done(ev->u.cmd_res.tid,
				      ev->u.cmd_res.cid,
				      ev->u.cmd_res.devid,
				      ev->u.cmd_res.result, ev->u.cmd_res.len,
				      ev->u.cmd_res.offset,
				      ev->u.cmd_res.uaddr, ev->u.cmd_res.rw,
				      ev->u.cmd_res.try_map);
		if (err) {
			eprintk("%llx %d\n",
				(unsigned long long) ev->u.cmd_res.cid, err);
			BUG();
		}

		break;
	default:
		eprintk("unknown type %d\n", nlh->nlmsg_type);
		err = -EINVAL;
	}

	return err;
}

static int event_recv_skb(struct sk_buff *skb)
{
	int err;
	uint32_t rlen;
	struct nlmsghdr	*nlh;

	while (skb->len >= NLMSG_SPACE(0)) {
		nlh = (struct nlmsghdr *) skb->data;
		if (nlh->nlmsg_len < sizeof(*nlh) || skb->len < nlh->nlmsg_len)
			return 0;
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;
		err = event_recv_msg(skb, nlh);

		dprintk("%d %d\n", nlh->nlmsg_type, err);
		/*
		 * TODO for passthru commands the lower level should
		 * probably handle the result or we should modify this
		 */
		if (nlh->nlmsg_type != TGT_UEVENT_CMD_RES &&
		    nlh->nlmsg_type != TGT_UEVENT_TARGET_PASSTHRU) {
			struct tgt_event ev;

			memset(&ev, 0, sizeof(ev));
			ev.k.event_res.err = err;
			send_event_res(TGT_KEVENT_RESPONSE, &ev, NULL, 0,
				       GFP_KERNEL | __GFP_NOFAIL,
				       nlh->nlmsg_pid);
		}
		skb_pull(skb, rlen);
	}
	return 0;
}

static void event_recv(struct sock *sk, int length)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&sk->sk_receive_queue))) {
		if (event_recv_skb(skb) && skb->len)
			skb_queue_head(&sk->sk_receive_queue, skb);
		else
			kfree_skb(skb);
	}
}

void __exit tgt_nl_exit(void)
{
	free_page((unsigned long) zero_page);
	sock_release(nls->sk_socket);
}

int __init tgt_nl_init(void)
{
	zero_page = (void *) get_zeroed_page(GFP_KERNEL);
	if (!zero_page)
		return -ENOMEM;

	nls = netlink_kernel_create(NETLINK_TGT, 1, event_recv, THIS_MODULE);
	if (!nls) {
		eprintk("Cannot create netlink socket %d\n", NETLINK_TGT);
		free_page((unsigned long) zero_page);
		return -ENOMEM;
	}

	return 0;
}

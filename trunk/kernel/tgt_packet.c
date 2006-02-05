/*
 * Target packet socket code
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 */

#include <net/sock.h>
#include <net/af_packet.h>
#include <linux/if_packet.h>

#include <tgt.h>
#include <tgt_target.h>
#include <tgt_if.h>
#include <tgt_protocol.h>
#include "tgt_priv.h"

int tgt_uspace_cmd_send(struct tgt_cmd *cmd, gfp_t gfp_mask)
{
	struct tgt_protocol *proto = cmd->session->target->proto;
	int proto_pdu_size = proto->uspace_pdu_size;
	struct sock *sk = cmd->session->target->sock->sk;
	struct tpacket_hdr *h;
	struct tgt_event *ev;
	char *pdu;

	h = packet_frame(sk);
	if (IS_ERR(h)) {
		eprintk("Queue is full\n");
		return PTR_ERR(h);
	}

	ev = (struct tgt_event *) ((char *) h + TPACKET_HDRLEN);
	pdu = (char *) ev->data;

	ev->k.cmd_req.tid = cmd->session->target->tid;
	ev->k.cmd_req.cid = cmd_tag(cmd);
	ev->k.cmd_req.typeid = cmd->session->target->typeid;
	ev->k.cmd_req.data_len = cmd->bufflen;

	proto->uspace_pdu_build(cmd, pdu);

	dprintk("%d %llu %d %d\n", ev->k.cmd_req.tid, ev->k.cmd_req.cid,
		ev->k.cmd_req.typeid, ev->k.cmd_req.data_len);

	h->tp_status = TP_STATUS_USER;
	mb();
	{
		struct page *p_start, *p_end;
		char *h_end = pdu + TPACKET_HDRLEN + proto_pdu_size - 1;

		p_start = virt_to_page(h);
		p_end = virt_to_page(h_end);
		while (p_start <= p_end) {
			flush_dcache_page(p_start);
			p_start++;
		}
	}

	sk->sk_data_ready(sk, 0);

	return 0;
}
EXPORT_SYMBOL_GPL(tgt_uspace_cmd_send);

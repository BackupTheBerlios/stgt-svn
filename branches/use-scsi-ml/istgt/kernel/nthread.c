/*
 * Network thread.
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */

#include <linux/sched.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <asm/ioctls.h>
#include <asm/scatterlist.h>

#include <iscsi.h>
#include <digest.h>

DECLARE_WAIT_QUEUE_HEAD(iscsi_ctl_wait);

enum daemon_state_bit {
	D_ACTIVE,
	D_DATA_READY,
};

void nthread_wakeup(struct iscsi_session *session)
{
	struct network_thread_info *info = &session->nthread_info;

	spin_lock_bh(&info->nthread_lock);
	set_bit(D_DATA_READY, &info->flags);
	wake_up_process(info->task);
	spin_unlock_bh(&info->nthread_lock);
}

static inline void iscsi_conn_init_read(struct iscsi_conn *conn, void *data, size_t len)
{
	len = (len + 3) & -4; // XXX ???
	conn->read_iov[0].iov_base = data;
	conn->read_iov[0].iov_len = len;
	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_msg.msg_iovlen = 1;
	conn->read_size = (len + 3) & -4;
}

static void iscsi_conn_read_ahs(struct iscsi_conn *conn, struct istgt_cmd *cmnd)
{
	cmnd->pdu.ahs = kmalloc(cmnd->pdu.ahssize, __GFP_NOFAIL|GFP_KERNEL);
	BUG_ON(!cmnd->pdu.ahs);
	iscsi_conn_init_read(conn, cmnd->pdu.ahs, cmnd->pdu.ahssize);
}

static struct istgt_cmd * iscsi_get_send_cmnd(struct iscsi_conn *conn)
{
	struct istgt_cmd *cmnd = NULL;

	spin_lock(&conn->list_lock);
	if (!list_empty(&conn->write_list)) {
		cmnd = list_entry(conn->write_list.next, struct istgt_cmd, list);
		list_del_init(&cmnd->list);
	}
	spin_unlock(&conn->list_lock);

	return cmnd;
}

static int is_data_available(struct iscsi_conn *conn)
{
	int avail, res;
	mm_segment_t oldfs;
	struct socket *sock = conn->sock;

	oldfs = get_fs();
	set_fs(get_ds());
	res = sock->ops->ioctl(sock, SIOCINQ, (unsigned long) &avail);
	set_fs(oldfs);
	return (res >= 0) ? avail : res;
}

static void forward_iov(struct msghdr *msg, int len)
{
	while (msg->msg_iov->iov_len <= len) {
		len -= msg->msg_iov->iov_len;
		msg->msg_iov++;
		msg->msg_iovlen--;
	}

	msg->msg_iov->iov_base = (char *) msg->msg_iov->iov_base + len;
	msg->msg_iov->iov_len -= len;
}

static int do_recv(struct iscsi_conn *conn, int state)
{
	mm_segment_t oldfs;
	struct msghdr msg;
	struct iovec iov[ISCSI_CONN_IOV_MAX];
	int i, len, res;

	if (!test_bit(CONN_ACTIVE, &conn->state)) {
		res = -EIO;
		goto out;
	}

	if (is_data_available(conn) <= 0) {
		res = -EAGAIN;
		goto out;
	}

	msg.msg_iov = iov;
	msg.msg_iovlen = min_t(size_t, conn->read_msg.msg_iovlen, ISCSI_CONN_IOV_MAX);
	for (i = 0, len = 0; i < msg.msg_iovlen; i++) {
		iov[i] = conn->read_msg.msg_iov[i];
		len += iov[i].iov_len;
	}

	oldfs = get_fs();
	set_fs(get_ds());
	res = sock_recvmsg(conn->sock, &msg, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	set_fs(oldfs);

	if (res <= 0) {
		switch (res) {
		case -EAGAIN:
		case -ERESTARTSYS:
			break;
		default:
			eprintk("%d\n", res);
			conn_close(conn);
			break;
		}
	} else {
		conn->read_size -= res;
		if (conn->read_size)
			forward_iov(&conn->read_msg, res);
		else
			conn->read_state = state;
	}

out:
	dprintk("%d\n", res);

	return res;
}

enum rx_state {
	RX_INIT_BHS, /* Must be zero. */
	RX_BHS,

	RX_INIT_AHS,
	RX_AHS,

	RX_INIT_HDIGEST,
	RX_HDIGEST,
	RX_CHECK_HDIGEST,

	RX_INIT_DATA,
	RX_DATA,

	RX_INIT_DDIGEST,
	RX_DDIGEST,
	RX_CHECK_DDIGEST,

	RX_END,
};

static void rx_ddigest(struct iscsi_conn *conn, int state)
{
	struct istgt_cmd *cmnd = conn->read_cmnd;
	int res = digest_rx_data(cmnd);

	if (!res)
		conn->read_state = state;
	else
		conn_close(conn);
}

static void rx_hdigest(struct iscsi_conn *conn, int state)
{
	struct istgt_cmd *cmnd = conn->read_cmnd;
	int res = digest_rx_header(cmnd);

	if (!res)
		conn->read_state = state;
	else
		conn_close(conn);
}

static struct istgt_cmd *create_cmnd(struct iscsi_conn *conn)
{
	struct istgt_cmd *cmnd;

	cmnd = cmnd_alloc(conn, 1);
	iscsi_conn_init_read(cmnd->conn, &cmnd->pdu.bhs, sizeof(cmnd->pdu.bhs));
	conn->read_state = RX_BHS;

	return cmnd;
}

static int recv(struct iscsi_conn *conn)
{
	struct istgt_cmd *cmnd = conn->read_cmnd;
	int hdigest, ddigest, res = 1;

	if (!test_bit(CONN_ACTIVE, &conn->state))
		return -EIO;

	hdigest = conn->hdigest_type & DIGEST_NONE ? 0 : 1;
	ddigest = conn->ddigest_type & DIGEST_NONE ? 0 : 1;

	switch (conn->read_state) {
	case RX_INIT_BHS:
		BUG_ON(cmnd);
		cmnd = conn->read_cmnd = create_cmnd(conn);
	case RX_BHS:
		res = do_recv(conn, RX_INIT_AHS);
		if (res <= 0 || conn->read_state != RX_INIT_AHS)
			break;
	case RX_INIT_AHS:
		iscsi_cmnd_get_length(&cmnd->pdu);
		if (cmnd->pdu.ahssize) {
			iscsi_conn_read_ahs(conn, cmnd);
			conn->read_state = RX_AHS;
		} else
			conn->read_state = hdigest ? RX_INIT_HDIGEST : RX_INIT_DATA;

		if (conn->read_state != RX_AHS)
			break;
	case RX_AHS:
		res = do_recv(conn, hdigest ? RX_INIT_HDIGEST : RX_INIT_DATA);
		if (res <= 0 || conn->read_state != RX_INIT_HDIGEST)
			break;
	case RX_INIT_HDIGEST:
		iscsi_conn_init_read(conn, &cmnd->hdigest, sizeof(uint32_t));
		conn->read_state = RX_HDIGEST;
	case RX_HDIGEST:
		res = do_recv(conn, RX_CHECK_HDIGEST);
		if (res <= 0 || conn->read_state != RX_CHECK_HDIGEST)
			break;
	case RX_CHECK_HDIGEST:
		rx_hdigest(conn, RX_INIT_DATA);
		if (conn->read_state != RX_INIT_DATA)
			break;
	case RX_INIT_DATA:
		cmnd_rx_start(cmnd);
		conn->read_state = cmnd->pdu.datasize ? RX_DATA : RX_END;
		if (conn->read_state != RX_DATA)
			break;
	case RX_DATA:
		res = do_recv(conn, ddigest ? RX_INIT_DDIGEST : RX_END);
		if (res <= 0 || conn->read_state != RX_INIT_DDIGEST)
			break;
	case RX_INIT_DDIGEST:
		iscsi_conn_init_read(conn, &cmnd->ddigest, sizeof(uint32_t));
		conn->read_state = RX_DDIGEST;
	case RX_DDIGEST:
		res = do_recv(conn, RX_CHECK_DDIGEST);
		if (res <= 0 || conn->read_state != RX_CHECK_DDIGEST)
			break;
	case RX_CHECK_DDIGEST:
		rx_ddigest(conn, RX_END);
		break;
	default:
		eprintk("%d %d %x\n", res, conn->read_state, cmd_opcode(cmnd));
		BUG_ON(1);
	}

	if (res <= 0)
		return res;

	if (conn->read_state != RX_END)
		return res;

	if (conn->read_size) {
		eprintk("%d %x %d\n", res, cmd_opcode(cmnd), conn->read_size);
		BUG_ON(1);
	}

	cmnd_rx_end(cmnd);
	if (conn->read_size) {
		eprintk("%x %d\n", cmd_opcode(cmnd), conn->read_size);
		conn->read_state = RX_DATA;
		return 1;
	}

	conn->read_cmnd = NULL;
	conn->read_state = RX_INIT_BHS;

	return 0;
}

/* This is taken from the Ardis code. */
static int write_data(struct iscsi_conn *conn)
{
	mm_segment_t oldfs;
	struct file *file;
	struct socket *sock;
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	struct scatterlist *sg;
	struct iovec *iop;
	int saved_size, size, sendsize;
	int offset, idx;
	int flags, res;

	file = conn->file;
	saved_size = size = conn->write_size;
	iop = conn->write_iop;

	if (iop) while (1) {
		loff_t off = 0;
		unsigned long count;
		struct iovec *vec;
		int rest;

		vec = iop;
		for (count = 0; vec->iov_len; count++, vec++)
			;
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		res = vfs_writev(file, (struct iovec __user *) iop, count, &off);
		set_fs(oldfs);
		dprintk("%#Lx:%u: %d(%ld)\n",
			(unsigned long long) conn->session->sid, conn->cid,
			res, (long) iop->iov_len);
		if (unlikely(res <= 0)) {
			if (res == -EAGAIN || res == -EINTR) {
				conn->write_iop = iop;
				goto out_iov;
			}
			goto err;
		}

		rest = res;
		size -= res;
		while (iop->iov_len <= rest && rest) {
			rest -= iop->iov_len;
			iop++;
		}
		iop->iov_base += rest;
		iop->iov_len -= rest;

		if (!iop->iov_len) {
			conn->write_iop = NULL;
			if (size)
				break;
			goto out_iov;
		}
	}

	sg = conn->write_sg;
	if (!sg) {
		eprintk("warning data missing!\n");
		return 0;
	}
	offset = conn->write_offset;
	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	sock = conn->sock;
	sendpage = sock->ops->sendpage ? : sock_no_sendpage;
	flags = MSG_DONTWAIT;

	while (1) {
		sendsize = PAGE_CACHE_SIZE - offset;
		if (size <= sendsize) {
			res = sendpage(sock, sg[idx].page, offset, size, flags);
			dprintk("%s %#Lx:%u: %d(%lu,%u,%u)\n",
				sock->ops->sendpage ? "sendpage" : "writepage",
				(unsigned long long ) conn->session->sid, conn->cid,
				res, sg[idx].page->index, offset, size);
			if (unlikely(res <= 0)) {
				if (res == -EAGAIN || res == -EINTR) {
					goto out;
				}
				goto err;
			}
			if (res == size) {
				conn->write_sg = NULL;
				conn->write_size = 0;
				return saved_size;
			}
			offset += res;
			size -= res;
			continue;
		}

		res = sendpage(sock, sg[idx].page, offset, sendsize, flags | MSG_MORE);
		dprintk("%s %#Lx:%u: %d(%lu,%u,%u)\n",
			sock->ops->sendpage ? "sendpage" : "writepage",
			(unsigned long long ) conn->session->sid, conn->cid,
			res, sg[idx].page->index, offset, sendsize);
		if (unlikely(res <= 0)) {
			if (res == -EAGAIN || res == -EINTR) {
				goto out;
			}
			goto err;
		}
		if (res == sendsize) {
			idx++;
			offset = 0;
		} else
			offset += res;
		size -= res;
	}
 out:
	conn->write_offset = (idx << PAGE_CACHE_SHIFT) + offset;
 out_iov:
	conn->write_size = size;
	if ((saved_size == size) && res == -EAGAIN)
		return res;

	return saved_size - size;

 err:
	eprintk("error %d at %#Lx:%u\n", res,
		(unsigned long long) conn->session->sid, conn->cid);
	return res;
}

static void exit_tx(struct iscsi_conn *conn, int res)
{
	if (res > 0)
		return;

	switch (res) {
	case -EAGAIN:
	case -ERESTARTSYS:
		break;
	default:
		eprintk("%d %d %d\n", conn->write_size, conn->write_state, res);
		conn_close(conn);
		break;
	}
}

static int tx_ddigest(struct istgt_cmd *cmnd, int state)
{
	int res, rest = cmnd->conn->write_size;
	struct msghdr msg = {.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT};
	struct kvec iov;

	iov.iov_base = (char *) (&cmnd->ddigest) + (sizeof(uint32_t) - rest);
	iov.iov_len = rest;

	res = kernel_sendmsg(cmnd->conn->sock, &msg, &iov, 1, rest);

	if (res > 0) {
		cmnd->conn->write_size -= res;
		if (!cmnd->conn->write_size)
			cmnd->conn->write_state = state;
	} else
		exit_tx(cmnd->conn, res);

	return res;
}

static void init_tx_hdigest(struct istgt_cmd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iovec *iop;

	if (conn->hdigest_type & DIGEST_NONE)
		return;

	digest_tx_header(cmnd);

	for (iop = conn->write_iop; iop->iov_len; iop++)
		;
	iop->iov_base = &(cmnd->hdigest);
	iop->iov_len = sizeof(uint32_t);
	conn->write_size += sizeof(uint32_t);
	iop++;
	iop->iov_len = 0;

	return;
}

enum tx_state {
	TX_INIT, /* Must be zero. */
	TX_BHS_DATA,
	TX_INIT_DDIGEST,
	TX_DDIGEST,
	TX_END,
};

static int do_send(struct iscsi_conn *conn, int state)
{
	int res;

	res = write_data(conn);

	if (res > 0) {
		if (!conn->write_size)
			conn->write_state = state;
	} else
		exit_tx(conn, res);

	return res;
}

static int send(struct iscsi_conn *conn)
{
	struct istgt_cmd *cmnd = conn->write_cmnd;
	int ddigest, res = 0;

	ddigest = conn->ddigest_type != DIGEST_NONE ? 1 : 0;

	switch (conn->write_state) {
	case TX_INIT:
		BUG_ON(cmnd);
		cmnd = conn->write_cmnd = iscsi_get_send_cmnd(conn);
		if (!cmnd)
			return 0;
		cmnd_tx_start(cmnd);
		init_tx_hdigest(cmnd);
		conn->write_state = TX_BHS_DATA;
	case TX_BHS_DATA:
		res = do_send(conn, ddigest && cmnd->pdu.datasize ? TX_INIT_DDIGEST : TX_END);
		if (res <= 0 || conn->write_state != TX_INIT_DDIGEST)
			break;
	case TX_INIT_DDIGEST:
		digest_tx_data(cmnd);
		BUG_ON(cmnd->conn->write_size);
		cmnd->conn->write_size += sizeof(uint32_t);
		conn->write_state = TX_DDIGEST;
	case TX_DDIGEST:
		res = tx_ddigest(cmnd, TX_END);
		break;
	default:
		eprintk("%d %d %x\n", res, conn->write_state, cmd_opcode(cmnd));
		BUG_ON(1);
	}

	if (res <= 0)
		return res;

	if (conn->write_state != TX_END)
		return res;

	if (conn->write_size) {
		eprintk("%d %x %u\n", res, cmd_opcode(cmnd), conn->write_size);
		BUG_ON(conn->write_size);
	}
	cmnd_tx_end(cmnd);
	cmnd_release(cmnd, 0);
	conn->write_cmnd = NULL;
	conn->write_state = TX_INIT;

	return 0;
}

static void process_io(struct iscsi_conn *conn)
{
	int res, wakeup = 0;

	res = recv(conn);

	if (is_data_available(conn) > 0 || res > 0)
		wakeup = 1;

	if (!test_bit(CONN_ACTIVE, &conn->state)) {
		wakeup = 1;
		goto out;
	}

	res = send(conn);

	if (!list_empty(&conn->write_list) || conn->write_cmnd)
		wakeup = 1;

out:
	if (wakeup)
		nthread_wakeup(conn->session);

	return;
}

static void close_conn(struct iscsi_conn *conn)
{
	struct iscsi_session *session = conn->session;
	struct istgt_cmd *cmnd;

	conn->sock->ops->shutdown(conn->sock, 2);

	write_lock(&conn->sock->sk->sk_callback_lock);
	conn->sock->sk->sk_state_change = session->nthread_info.old_state_change;
	conn->sock->sk->sk_data_ready = session->nthread_info.old_data_ready;
	write_unlock(&conn->sock->sk->sk_callback_lock);

	fput(conn->file);
	conn->file = NULL;
	conn->sock = NULL;

	while (atomic_read(&conn->nr_busy_cmnds))
		yield();

	while (!list_empty(&conn->pdu_list)) {
		cmnd = list_entry(conn->pdu_list.next, struct istgt_cmd, conn_list);

		list_del_init(&cmnd->list);
		cmnd_release(cmnd, 1);
	}

	if (atomic_read(&conn->nr_cmnds)) {
		eprintk("%u\n", atomic_read(&conn->nr_cmnds));
		list_for_each_entry(cmnd, &conn->pdu_list, conn_list)
			eprintk("%x %x\n", cmd_opcode(cmnd), cmd_itt(cmnd));
		BUG_ON(1);
	}

	eprintk("%llu %d\n", session->sid, conn->cid);
	conn_free(conn);
}

static int istd(void *arg)
{
	struct iscsi_session *session = arg;
	struct network_thread_info *info = &session->nthread_info;
	struct iscsi_conn *conn, *tmp;

	__set_current_state(TASK_RUNNING);
	do {
		spin_lock_bh(&info->nthread_lock);
		__set_current_state(TASK_INTERRUPTIBLE);

		if (!test_bit(D_DATA_READY, &info->flags)) {
			spin_unlock_bh(&info->nthread_lock);
			schedule();
			spin_lock_bh(&info->nthread_lock);
		}
		__set_current_state(TASK_RUNNING);
		clear_bit(D_DATA_READY, &info->flags);
		spin_unlock_bh(&info->nthread_lock);

		down(&session->target_sem);
		list_for_each_entry_safe(conn, tmp, &info->active_conns, poll_list) {
			if (test_bit(CONN_ACTIVE, &conn->state))
				process_io(conn);
			else
				close_conn(conn);
		}
		up(&session->target_sem);

	} while (!kthread_should_stop());

	return 0;
}

int nthread_init(struct iscsi_session *session)
{
	struct network_thread_info *info = &session->nthread_info;

	info->flags = 0;
	info->task = NULL;

	info->old_state_change = NULL;
	info->old_data_ready = NULL;

	INIT_LIST_HEAD(&info->active_conns);

	spin_lock_init(&info->nthread_lock);

	return 0;
}

int nthread_start(struct iscsi_session *session)
{
	int err = 0;
	struct network_thread_info *info = &session->nthread_info;
	struct task_struct *task;

	if (info->task) {
		eprintk("Target (%llu) already runs\n", session->sid);
		return -EALREADY;
	}

	task = kthread_run(istd, session, "istd%llu", session->sid);

	if (IS_ERR(task))
		err = PTR_ERR(task);
	else
		info->task = task;

	return err;
}

int nthread_stop(struct iscsi_session *session)
{
	int err;
	struct network_thread_info *info = &session->nthread_info;

	if (!info->task)
		return -ESRCH;

	err = kthread_stop(info->task);

	if (!err)
		info->task = NULL;

	return err;
}
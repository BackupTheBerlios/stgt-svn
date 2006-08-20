/*
 * Software iSCSI target library
 *
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2005 Mike Christie <michaelc@cs.wisc.edu>
 * This code is licenced under the GPL.
 *
 * This is based on Ardis's iSCSI implementation.
 *   http://www.ardistech.com/iscsi/
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>

#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iscsid.h"

#define ISCSI_LISTEN_PORT	3260

#define LISTEN_MAX	4
#define INCOMING_MAX	32

enum {
	POLL_LISTEN,
	POLL_INCOMING = POLL_LISTEN + LISTEN_MAX,
	POLL_MAX = POLL_INCOMING + INCOMING_MAX,
};

static struct connection *incoming[INCOMING_MAX];

static void set_non_blocking(int fd)
{
	int res = fcntl(fd, F_GETFL);

	if (res != -1) {
		res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			dprintf("unable to set fd flags (%s)!\n", strerror(errno));
	} else
		dprintf("unable to get fd flags (%s)!\n", strerror(errno));
}

static void listen_socket_create(struct pollfd *pfds)
{
	struct addrinfo hints, *res, *res0;
	char servname[64];
	int i, sock, opt;

	memset(servname, 0, sizeof(servname));
	snprintf(servname, sizeof(servname), "%d", ISCSI_LISTEN_PORT);

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(NULL, servname, &hints, &res0)) {
		eprintf("unable to get address info (%s)!\n", strerror(errno));
		exit(1);
	}

	for (i = 0, res = res0; res && i < LISTEN_MAX; i++, res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sock < 0) {
			eprintf("unable to create server socket (%s) %d %d %d!\n",
				  strerror(errno), res->ai_family,
				  res->ai_socktype, res->ai_protocol);
			continue;
		}

		opt = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
			dprintf("unable to set SO_REUSEADDR on server socket (%s)!\n",
				    strerror(errno));
		opt = 1;
		if (res->ai_family == AF_INET6 &&
		    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)))
			continue;

		if (bind(sock, res->ai_addr, res->ai_addrlen)) {
			eprintf("unable to bind server socket (%s)!\n", strerror(errno));
			continue;
		}

		if (listen(sock, INCOMING_MAX)) {
			eprintf("unable to listen to server socket (%s)!\n", strerror(errno));
			continue;
		}

		set_non_blocking(sock);

		pfds[i].fd = sock;
		pfds[i].events = POLLIN;
	}

	freeaddrinfo(res0);
}

static void accept_connection(struct pollfd *pfds, int afd)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	struct pollfd *pfd;
	struct connection *conn;
	int fd, i;

	eprintf("%d\n", afd);

	for (i = 0; i < INCOMING_MAX; i++) {
		if (!incoming[i])
			break;
	}
	if (i >= INCOMING_MAX) {
		eprintf("unable to find incoming slot %d\n", i);
		return;
	}

	namesize = sizeof(from);
	fd = accept(afd, (struct sockaddr *) &from, &namesize);
	if (fd < 0) {
		eprintf("%s\n", strerror(errno));
		return;
	}

	conn = conn_alloc();
	if (!conn) {
		eprintf("fail to allocate conn\n");
		goto out;
	}
	conn->fd = fd;
	incoming[i] = conn;
	conn_read_pdu(conn);

	set_non_blocking(fd);
	pfd = &pfds[POLL_INCOMING + i];
	pfd->fd = fd;
	pfd->events = POLLIN;
	pfd->revents = 0;

	return;
out:
	close(fd);
	return;
}

static void iscsi_rx(struct pollfd *pfd, struct connection *conn)
{
	int res;

	switch (conn->rx_iostate) {
	case IOSTATE_READ_BHS:
	case IOSTATE_READ_AHS_DATA:
	read_again:
		res = read(pfd->fd, conn->buffer, conn->rwsize);
		if (res <= 0) {
			if (res == 0 || (errno != EINTR && errno != EAGAIN))
				conn->state = STATE_CLOSE;
			else if (errno == EINTR)
				goto read_again;
			break;
		}
		conn->rwsize -= res;
		conn->buffer += res;
		if (conn->rwsize)
			break;

		switch (conn->rx_iostate) {
		case IOSTATE_READ_BHS:
			conn->rx_iostate = IOSTATE_READ_AHS_DATA;
			conn->req.ahssize = conn->req.bhs.hlength * 4;
			conn->req.datasize = ntoh24(conn->req.bhs.dlength);
			conn->rwsize = (conn->req.ahssize + conn->req.datasize + 3) & -4;

			if (conn->req.ahssize) {
				eprintf("FIXME: we cannot handle ahs\n");
				conn->state = STATE_CLOSE;
				break;
			}

			if (conn->state == STATE_SCSI) {
				res = iscsi_cmd_rx_start(conn);
				if (res) {
					conn->state = STATE_CLOSE;
					break;
				}
			}
			if (conn->rwsize) {
				if (conn->state == STATE_SCSI) {
					dprintf("%d\n", conn->rwsize);
				} else {
					conn->buffer = conn->req_buffer;
					conn->req.ahs = conn->buffer;
				}
				conn->req.data =
					conn->buffer + conn->req.ahssize;
				goto read_again;
			}

		case IOSTATE_READ_AHS_DATA:
			if (conn->state == STATE_SCSI) {
				int rsp;

				conn_write_pdu(conn, 1);
				pfd->events = POLLOUT;
				res = iscsi_cmd_rx_done(conn, &rsp);
				if (!res && !rsp) {
					conn_read_pdu(conn);
					pfd->events = POLLIN;
				}
			} else {
				conn_write_pdu(conn, 1);
				pfd->events = POLLOUT;
				res = cmnd_execute(conn);
			}

			if (res)
				conn->state = STATE_CLOSE;
			break;
		break;
		}
	}
}

static void iscsi_tx(struct pollfd *pfd, struct connection *conn)
{
	int opt, res, more_rsp;

	switch (conn->tx_iostate) {
	case IOSTATE_WRITE_BHS:
	case IOSTATE_WRITE_AHS:
	case IOSTATE_WRITE_DATA:
	write_again:
		if (conn->state == STATE_SCSI)
			dprintf("%d %d %d\n", conn->rwsize, conn->rsp.ahssize,
				conn->rsp.datasize);
		opt = 1;
		setsockopt(pfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
		res = write(pfd->fd, conn->buffer, conn->rwsize);
		if (res < 0) {
			if (errno != EINTR && errno != EAGAIN)
				conn->state = STATE_CLOSE;
			else if (errno == EINTR)
				goto write_again;
			break;
		}

		conn->rwsize -= res;
		conn->buffer += res;
		if (conn->rwsize)
			goto write_again;

		switch (conn->tx_iostate) {
		case IOSTATE_WRITE_BHS:
			if (conn->rsp.ahssize) {
				conn->tx_iostate = IOSTATE_WRITE_AHS;
				conn->buffer = conn->rsp.ahs;
				conn->rwsize = conn->rsp.ahssize;
				goto write_again;
			}
		case IOSTATE_WRITE_AHS:
			if (conn->rsp.datasize) {
				int pad;

				conn->tx_iostate = IOSTATE_WRITE_DATA;
				conn->buffer = conn->rsp.data;
				conn->rwsize = conn->rsp.datasize;
				pad = conn->rwsize & (PAD_WORD_LEN - 1);
				if (pad) {
					for (pad = PAD_WORD_LEN - pad; pad; pad--)
						*((uint8_t *)conn->buffer + conn->rwsize++) = 0;
				}
				goto write_again;
			}
		case IOSTATE_WRITE_DATA:
			opt = 0;
			setsockopt(pfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
			cmnd_finish(conn);

			switch (conn->state) {
			case STATE_KERNEL:
				res = conn_take_fd(conn, pfd->fd);
				if (res)
					conn->state = STATE_CLOSE;
				else {
					conn->state = STATE_SCSI;
					conn_read_pdu(conn);
					pfd->events = POLLIN;
				}
				break;
			case STATE_EXIT:
			case STATE_CLOSE:
				break;
			case STATE_SCSI:
				iscsi_cmd_tx_done(conn, &more_rsp);
				if (more_rsp) {
					conn_write_pdu(conn, 0);
					goto write_again;
				}
			default:
				conn_read_pdu(conn);
				pfd->events = POLLIN;
				break;
			}
			break;
		}

		break;
	default:
		eprintf("illegal iostate %d\n", conn->tx_iostate);
		conn->state = STATE_CLOSE;
	}
}

void iscsi_event_handle(struct pollfd *pfds)
{
	struct session *session;
	struct connection *conn;
	struct pollfd *pfd;
	int i;

	for (i = 0; i < LISTEN_MAX; i++) {
		if (pfds[POLL_LISTEN + i].revents)
			accept_connection(pfds, pfds[POLL_LISTEN + i].fd);
	}

	for (i = 0; i < INCOMING_MAX; i++) {
		conn = incoming[i];
		pfd = &pfds[POLL_INCOMING + i];
		if (!conn || !pfd->revents)
			continue;

		if (pfd->revents & POLLIN)
			iscsi_rx(pfd, conn);
		if (pfd->revents & POLLOUT)
			iscsi_tx(pfd, conn);
		pfd->revents = 0;

		if (conn->state == STATE_CLOSE) {
			dprintf("connection closed\n");
			session = conn->session;
			conn_free_pdu(conn);
			conn_free(conn);
			close(pfd->fd);
			pfd->fd = -1;
			incoming[i] = NULL;
			if (session)
				session_destroy(session);
		}
	}
}

int iscsi_poll_init(struct pollfd *pfd)
{
	int i;

	listen_socket_create(pfd + POLL_LISTEN);

	for (i = 0; i < INCOMING_MAX; i++) {
		pfd[POLL_INCOMING + i].fd = -1;
		pfd[POLL_INCOMING + i].events = 0;
		incoming[i] = NULL;
	}

	return 0;
}

int iscsi_init(int *npfd)
{
	*npfd = POLL_MAX;

	return 0;
}

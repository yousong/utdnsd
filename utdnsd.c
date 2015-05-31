#include <sys/types.h>			/* struct sockaddr_storage */
#include <sys/socket.h>			/* struct sockaddr_storage */
#include <arpa/inet.h>			/* htons(), ntohs() */
#include <netinet/tcp.h>		/* IPPROTO_TCP, TCP_NODELAY */
#include <unistd.h>			/* getopt(), getuid(), setuid(), setgid() */
#include <libgen.h>			/* basename() */
#include <signal.h>			/* signal() */
#include <sys/time.h>			/* struct timeval, */
#include <pwd.h>			/* struct passwd, getpwnam() */

#include <stdio.h>			/* fprintf() */
#include <stdlib.h>			/* srandom(), random(), exit(), strtoul() */
#include <string.h>			/* strchr(), strerror() */
#include <errno.h>			/* errno */
#include <stdint.h>
#include <stdbool.h>

#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/list.h>
#include <libubox/usock.h>
#include <libubox/utils.h>		/* clock_gettime() for Darwin */

#define __log(fmt, ...)	do {						\
	fprintf(stderr, fmt, ##__VA_ARGS__);				\
} while (0)
#define _log(level, fmt, ...)	do {					\
	if (!quiet)							\
		__log(level debugfmt fmt, debugargs, ##__VA_ARGS__);	\
} while (0)

#define error(fmt, ...)		_log("error: ", fmt, ##__VA_ARGS__)
#define warn(fmt, ...)		_log("warn: ", fmt, ##__VA_ARGS__)
#define info(fmt, ...)		_log("info: ", fmt, ##__VA_ARGS__)

#define rawinfo(fmt, ...)	__log(fmt, ##__VA_ARGS__)

#ifdef DEBUG
# define debug(fmt, ...)	_log("debug: ", fmt, ##__VA_ARGS__)
# define debugfmt		"%s:%d: "
# define debugargs		__func__, __LINE__
#else
# define debug(fmt, ...)
# define debugfmt		"%s"
# define debugargs		""
#endif

#ifndef __unused
#define __unused	__attribute__((unused))
#endif

#define SEC2USEC	1000000
#define NSEC2USEC	1000

#define DNSMSG_MIN_LEN		12
#define BUFSIZ_DNS		512
#define BUFSIZ_DNS_TCP		(BUFSIZ_DNS + 2)
#define NSERVERS		8				/* current default max upstream servers */
#define TCP_RECONNECT_DELAY	5000				/* milliseconds */
#define TCP_SHODDY_THRESHOLD	(5 * SEC2USEC)			/* microseconds */
struct dnssession {
	struct list_head	list;
	struct sockaddr_storage	srcaddr;
	uint8_t			reqbuf[BUFSIZ_DNS_TCP];
	int			reqlen;
	uint16_t		reqid;		/* BE reqid by client */
	uint16_t		reqid2;		/* BE reqid allocated by tcpsock */
	uint8_t			respbuf[BUFSIZ_DNS_TCP];
	int			resplen;
	int			respdata_len;	/* length of respbuf received */
	uint64_t		arrival_time;
};

enum {
	TCPSOCK_STATE_CLOSED,
	TCPSOCK_STATE_CONNECTED,
	TCPSOCK_STATE_SHODDY,		/* No further attempt with the server */
};

struct stats {
	long			num_served_sessions;
	long			total_sent;		/* bytes sent */
	long			total_received;		/* bytes received */
	long			num_reconnect;
	uint64_t		avg_wait_time;
};

struct tcpsock {
	struct list_head	list;	/* session staging area */
	int			nsess;
	struct ustream_fd	ufd;
	struct uloop_timeout	reconnect;
	unsigned long		reconnect_delay;
	char			*saddr;
	char			*sport;
	int			state;
	unsigned long		reqid;	/* reqid seed */
	struct stats		stats;
};
#define tcpsock_from_ustream(s)		container_of(s, struct tcpsock, ufd.stream)
#define tcpsock_from_reconnect(timeout)	container_of(timeout, struct tcpsock, reconnect)


const char *progname;
int quiet;
struct tcpsock tcpsocks[NSERVERS];
int ntcpsocks;
int shoddy_tcpsocks;

struct uloop_fd udpsock;
LIST_HEAD(list_dnssession_done);

int max_reconnect_delay = TCP_RECONNECT_DELAY;
uint64_t tcp_shoddy_threshold = TCP_SHODDY_THRESHOLD;

static int init_tcpsock(struct tcpsock *tcpsock, char *saddrport);
static void reinit_tcpsock(struct tcpsock *tcpsock, int state);
static void writereq(struct ustream *s, struct dnssession *sess);

#ifdef DEBUG
static void __unused hexdump(uint8_t *data, int len)
{
	int i = 0;
	rawinfo("== DUMP 0x%p/%d\n", data, len);
	for (i = 0; i < len; i++) {
		rawinfo("%02hhx%c", data[i], ((i & 0xf) != 0xf) ? ' ' : '\n');
	}
	rawinfo("===================\n");
}
#else
static void __unused hexdump(uint8_t *data, int len)
{
}
#endif

static void fill_dnsaddr(const char *saddrport, char **saddr, char **sport)
{
	*saddr = strdup(saddrport);
	if (!*saddr) {
		error("Allocating memory for address port failed.\n");
		exit(EXIT_FAILURE);
	}
	*sport = strchr(*saddr, ':');

	if (*sport) {
		**sport = '\0';
		*sport += 1;
	} else {
		*sport = "53";
	}
}

static uint16_t dnsmsg_get_id(uint8_t *msg, int msglen)
{
	return *(uint16_t *)msg;
}

static void dnsmsg_set_id(uint8_t *msg, int msglen, uint16_t nid)
{
	*(uint16_t *)msg = nid;
}

static uint16_t dnsmsg_alloc_id(struct tcpsock *tcpsock)
{
	tcpsock->reqid += 1;
	return (uint16_t)tcpsock->reqid;
}

static void gettime(uint64_t *usec)
{
	struct timespec ts;

	/*
	 * 2**64 / 1000000. / 3600. / 24.
	 *  213503982.33460128
	 */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	*usec = (uint64_t)ts.tv_sec * SEC2USEC + ts.tv_nsec / NSEC2USEC;
}

static inline uint64_t gettimediff(uint64_t t0, uint64_t t1)
{
	return t1 - t0;
}


static uint64_t tcpsock_estimate(struct tcpsock *tcpsock)
{
	struct list_head *staging = &tcpsock->list;
	uint64_t estimate;

	estimate = tcpsock->stats.avg_wait_time;
	if (!list_empty(staging)) {
		uint64_t curtime;
		uint64_t timediff;
		struct dnssession *sess;

		sess = list_first_entry(staging, struct dnssession, list);
		gettime(&curtime);
		timediff = gettimediff(sess->arrival_time, curtime);
		if (estimate < timediff) {
			estimate = timediff;
		}
		/*
		 * To be accurate, should also substract the elapsed time
		 * since the arrival of the 1st session in staging
		 */
		estimate *= tcpsock->nsess + 1;
	}
	return estimate;
}

static uint64_t tcpsock_estimate_threshold(struct tcpsock *tcpsock)
{
	return tcp_shoddy_threshold * (tcpsock->nsess + 1);
}

static int staging_dnssession(struct dnssession *sess)
{
	struct tcpsock *ans = NULL;
	uint64_t estimate = ~(uint64_t)0;
	int i;

	for (i = 0; i < ntcpsocks; i++) {
		struct tcpsock *tcpsock = &tcpsocks[i];
		uint64_t cur_estimate, cur_estimate_threshold;
		if (tcpsock->state != TCPSOCK_STATE_CONNECTED) {
			continue;
		}
		cur_estimate = tcpsock_estimate(tcpsock);
		cur_estimate_threshold = tcpsock_estimate_threshold(tcpsock);
		if (cur_estimate > cur_estimate_threshold) {
			reinit_tcpsock(tcpsock, TCPSOCK_STATE_SHODDY);
			continue;
		}
		if (estimate > cur_estimate) {
			estimate = cur_estimate;
			ans = tcpsock;
		}
	}

	if (!ans) {
		error("no usable TCP server!\n");
		return -1;
	}

	writereq(&ans->ufd.stream, sess);
	list_add_tail(&sess->list, &ans->list);
	ans->nsess += 1;
	return 0;
}

static struct dnssession *readreq(int udpsock)
{
	struct dnssession *sess;
	uint8_t *buf;
	int buflen;
	int msglen;
	socklen_t addrlen;

	sess = malloc(sizeof(*sess));
	if (!sess) {
		warn("allocating new dns session failed.\n");
		return NULL;
	}
	sess->resplen = 0;
	sess->respdata_len = 0;

	buf = sess->reqbuf + 2;
	buflen = sizeof(sess->reqbuf) - 2;
	addrlen = sizeof(sess->srcaddr);
	msglen = recvfrom(udpsock, buf, buflen, 0,
		(struct sockaddr *)&sess->srcaddr, &addrlen);
	if (msglen < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return NULL;
		error("recvfrom: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else if (msglen == 0) {
		error("recvfrom() returned 0!\n");
		exit(EXIT_FAILURE);
	} else if (msglen < DNSMSG_MIN_LEN) {
		error("recevied message too small: %d < %d\n", msglen, DNSMSG_MIN_LEN);
	} else {
		sess->reqlen = msglen;
		sess->reqid = dnsmsg_get_id(buf, msglen);
		gettime(&sess->arrival_time);
		debug("got valid request.\n");
		return sess;
	}

	free(sess);
	return NULL;
}

static void writereq(struct ustream *s, struct dnssession *sess)
{
	uint8_t *msg;
	int msglen;
	uint16_t reqid2;
	struct tcpsock *tcpsock;

	msg = sess->reqbuf;
	msglen = sess->reqlen;

	/* length */
	*(uint16_t *)msg = htons((uint16_t)msglen);

	/* msg */
	tcpsock = tcpsock_from_ustream(s);
	sess->reqid2 = reqid2 = dnsmsg_alloc_id(tcpsock);
	dnsmsg_set_id(msg + 2, msglen, reqid2);
	ustream_write(s, (char *)msg, msglen + 2, false);
	tcpsock->stats.total_sent += msglen + 2;

	return;
}

static struct dnssession *readresp(struct ustream *s)
{
	struct tcpsock *tcpsock = tcpsock_from_ustream(s);
	struct list_head *staging = &tcpsock->list;
	struct dnssession *sess;
	int available = ustream_pending_data(s, false);
	uint8_t *buf;
	int buflen;
	int readlen;

	if (available <= 0)
		return NULL;
	if (available > 0 && list_empty(staging)) {
		error("corruption: got data while there is no staging session.\n");
		return NULL;
	}
	sess = list_first_entry(staging, struct dnssession, list);

	if (!sess->resplen) {
		if (ustream_pending_data(s, false) < 2)
			return NULL;
		ustream_read(s, (char *)sess->respbuf, 2);
		sess->resplen = ntohs(*(uint16_t *)sess->respbuf);
		if (sess->resplen < DNSMSG_MIN_LEN || sess->resplen > sizeof(sess->respbuf)) {
			reinit_tcpsock(tcpsock, TCPSOCK_STATE_SHODDY);
			error("got vicious response from %s:%s.\n", tcpsock->saddr, tcpsock->sport);
			return NULL;
		}
	}

	buf = sess->respbuf + sess->respdata_len;
	buflen = sess->resplen - sess->respdata_len;
	readlen = ustream_read(s, (char *)buf, buflen);
	sess->respdata_len += readlen;

	if (sess->respdata_len == sess->resplen) {
		uint16_t respid = *(uint16_t *)sess->respbuf;
		uint64_t curtime;
		uint64_t oldavg;
		int oldserved;
		if (sess->reqid2 != respid) {
			reinit_tcpsock(tcpsock, TCPSOCK_STATE_CLOSED);
			error("response with unmatch id (%hu, %hu) from %s:%s.\n",
					sess->reqid2, respid, tcpsock->saddr, tcpsock->sport);
			return NULL;
		}
		gettime(&curtime);
		list_move_tail(&sess->list, &list_dnssession_done);
		tcpsock->nsess -= 1;
		tcpsock->stats.total_received += sess->resplen + 2;

		oldserved = tcpsock->stats.num_served_sessions;
		oldavg = tcpsock->stats.avg_wait_time / (oldserved + 1);
		oldavg *= oldserved;
		tcpsock->stats.avg_wait_time = oldavg + gettimediff(sess->arrival_time, curtime) / (oldserved + 1);

		tcpsock->stats.num_served_sessions += 1;
		debug("got response from %s:%s.\n", tcpsock->saddr, tcpsock->sport);
		return sess;
	} else {
		return NULL;
	}
}

static int writeresp(int udpsock, struct dnssession *sess)
{
	uint8_t *msg;
	int msglen;
	int writelen;
	int sent = -1;

	msg = sess->respbuf;
	msglen = sess->resplen;

	dnsmsg_set_id(msg, msglen, sess->reqid);
	writelen = sendto(udpsock, msg, msglen, 0,
			(struct sockaddr *)&sess->srcaddr, sizeof(sess->srcaddr));
	if (writelen < 0) {
		error("sendto: %s.\n", strerror(errno));
	} else if (writelen == 0) {
		error("sendto: returned 0.\n");
	} else if (writelen < msglen) {
		error("sendto: message not sent in a whole: %d < %d\n", writelen, msglen);
	} else {
		sent = 0;
		debug("sent response.\n");
	}

	return sent;
}

static void cb_udpsock_readable(int udpsock)
{
	struct dnssession *sess;

	while ((sess = readreq(udpsock))) {
		/* staging succeeded */
		if (staging_dnssession(sess) == 0)
			continue;

		/* no usable tcp server. quit reading more. */
		free(sess);
		break;
	}
}

static void cb_udpsock_writable(int udpsock)
{
	struct dnssession *sess;

	while (!list_empty(&list_dnssession_done)) {
		sess = list_first_entry(&list_dnssession_done, struct dnssession, list);
		if (!writeresp(udpsock, sess)) {
			list_del(&sess->list);
			free(sess);
		} else {
			break;
		}
	}
}

static void cb_uloop_udpsock(struct uloop_fd *fd, unsigned int events)
{
	int udpsockfd;

	if (fd->error) {
		error("UDP sock error occured.\n");
		exit(EXIT_FAILURE);
	}

	if (fd->eof) {
		error("EOF set on UDP socket!\n");
		exit(EXIT_FAILURE);
	}

	udpsockfd = fd->fd;
	if (events & ULOOP_WRITE) {
		cb_udpsock_writable(udpsockfd);
	}
	if (events & ULOOP_READ) {
		cb_udpsock_readable(udpsockfd);
	}
	if (list_empty(&list_dnssession_done)) {
		/* write out responses */
		uloop_fd_add(&udpsock, ULOOP_READ | ULOOP_ERROR_CB);
	}
}

static void tcpsock_notify_read(struct ustream *s, int bytes)
{
	while (readresp(s)) ;

	if (!list_empty(&list_dnssession_done)) {
		/* write out responses */
		uloop_fd_add(&udpsock, ULOOP_READ | ULOOP_WRITE | ULOOP_ERROR_CB);
	}
}

static void tcpsock_notify_write(struct ustream *s, int bytes)
{
	struct tcpsock * __unused tcpsock = tcpsock_from_ustream(s);

	debug("written %d bytes (still pending %d) to %s:%s.\n",
			bytes, ustream_pending_data(s, true),
			tcpsock->saddr, tcpsock->sport);
	/*FIXME tag me for more */
	/*struct tcpsock *tcpsock = tcpsock_from_ustream(s);*/
}

static void cb_tcpsock_reconnect(struct uloop_timeout *timeout)
{
	struct tcpsock *tcpsock = tcpsock_from_reconnect(timeout);

	if (init_tcpsock(tcpsock, NULL) < 0) {
		if (tcpsock->reconnect_delay < max_reconnect_delay) {
			tcpsock->reconnect_delay *= 2;
		} else {
			tcpsock->reconnect_delay = max_reconnect_delay;
		}
		uloop_timeout_set(timeout, tcpsock->reconnect_delay);
	} else {
		tcpsock->reconnect_delay = 500;
	}
	tcpsock->stats.num_reconnect += 1;
}

static void tcpsock_notify_state(struct ustream *s)
{
	struct tcpsock *tcpsock = tcpsock_from_ustream(s);

	if (s->eof || s->write_error) {
		error("TCP connection error: %s:%s: eof: %d, error: %d.\n",
				tcpsock->saddr, tcpsock->sport,
				s->eof, s->write_error);
	}

	reinit_tcpsock(tcpsock, TCPSOCK_STATE_CLOSED);
}

static void reinit_tcpsock(struct tcpsock *tcpsock, int state)
{
	struct dnssession *p, *n;
	struct list_head *staging = &tcpsock->list;

	tcpsock->state = state;
	list_for_each_entry_safe(p, n, staging, list) {
		list_del(&p->list);
		free(p);
	}
	tcpsock->nsess = 0;
	ustream_free(&tcpsock->ufd.stream);
	uloop_fd_delete(&tcpsock->ufd.fd);
	close(tcpsock->ufd.fd.fd);

	if (state != TCPSOCK_STATE_SHODDY) {
		/* reconnect */
		uloop_timeout_set(&tcpsock->reconnect, tcpsock->reconnect_delay);
	} else {
		shoddy_tcpsocks += 1;
		if (shoddy_tcpsocks >= ntcpsocks) {
			error("quit: all servers are marked shoddy.");
			exit(1);
		}
	}
}

static void init_udpsock(char *saddrport)
{
	char *saddr, *sport;
	int fd;

	fill_dnsaddr(saddrport, &saddr, &sport);
	fd = usock(USOCK_UDP | USOCK_SERVER, saddr, sport);
	if (fd < 0) {
		error("listen to UDP address %s:%s failed.\n", saddr, sport);
		exit(EXIT_FAILURE);
	} else {
		free(saddr);
	}
	udpsock.fd = fd;
	udpsock.cb = cb_uloop_udpsock;
	uloop_fd_add(&udpsock, ULOOP_READ | ULOOP_ERROR_CB);
}

static int init_tcpsock(struct tcpsock *tcpsock, char *saddrport)
{
	int fd;
	char *sremoteaddr, *sremoteport;

	if (saddrport) {
		fill_dnsaddr(saddrport, &sremoteaddr, &sremoteport);
		tcpsock->saddr = sremoteaddr;
		tcpsock->sport = sremoteport;
	} else {
		sremoteaddr = tcpsock->saddr;
		sremoteport = tcpsock->sport;
	}

	fd = usock(USOCK_TCP, sremoteaddr, sremoteport);
	if (fd < 0) {
		warn("%s to %s:%s failed.\n", !saddrport ? "reconnect" : "connect",
				sremoteaddr, sremoteport);
		return -1;
	} else {
		int optval = 1;
		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval))) {
			error("setsockopt(TCP_NODELAY)\n");
		}
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval))) {
			error("setsockopt(SO_KEEPALIVE)\n");
		}
		info("%s to %s:%s succeeded.\n", !saddrport ? "reconnect" : "connect",
				sremoteaddr, sremoteport);
	}

	srandom(random() ^ (long)&saddrport);
	tcpsock->reqid = random();
	tcpsock->reconnect.cb = cb_tcpsock_reconnect;
	tcpsock->reconnect_delay = 500;
	tcpsock->state = TCPSOCK_STATE_CONNECTED;
	tcpsock->stats.avg_wait_time = 0;

	tcpsock->ufd.stream.notify_read = tcpsock_notify_read;
	tcpsock->ufd.stream.notify_write = tcpsock_notify_write;
	tcpsock->ufd.stream.notify_state = tcpsock_notify_state;
	ustream_fd_init(&tcpsock->ufd, fd);
	INIT_LIST_HEAD(&tcpsock->list);

	return 0;
}

static void usage(void)
{
	fprintf(stderr, "Usage: %s [ -qh ] -l <host[:port]> [ -s <host[:port]> ... ] [ -t <seconds> ]\n", progname);
	fprintf(stderr, "  -l <host[:port]>  Address and port to listen to.\n");
	fprintf(stderr, "  -s <host[:port]>  Upstream DNS server we ask for service through TCP transport.\n");
	fprintf(stderr, "  -t <seconds>      Maximum delay for reconnect attempts (defaults to %ds).\n",
			TCP_RECONNECT_DELAY/1000);
	fprintf(stderr, "  -T <seconds>      Maximum delay before the link was considered shoddy (defaults to %ds).\n",
			TCP_SHODDY_THRESHOLD/SEC2USEC);
	fprintf(stderr, "  -q                Be quiet.\n");
	fprintf(stderr, "  -h                This output.\n");
}

static void cb_sighup(int signum)
{
	int i;
	uint64_t curtime;
	//int64_t idle;

	gettime(&curtime);
	rawinfo("== SIGUSR1 received, statistics follows\n");
	for (i = 0; i < ntcpsocks; i++) {
		struct tcpsock *tcpsock = &tcpsocks[i];
		int wbuf = ustream_pending_data(&tcpsock->ufd.stream, true);
		int rbuf = ustream_pending_data(&tcpsock->ufd.stream, false);
		rawinfo("> %15s:%-4s state:%d reconn:%-3ld served:%-5ld staging:%-3d estimate:%-2lld wbuf:%-3d rbuf:%-3d sent:%-8ld recv:%-8ld\n",
				tcpsock->saddr, tcpsock->sport, tcpsock->state, tcpsock->stats.num_reconnect,
				tcpsock->stats.num_served_sessions, tcpsock->nsess,
				tcpsock_estimate(tcpsock) / SEC2USEC,
				wbuf, rbuf,
				tcpsock->stats.total_sent, tcpsock->stats.total_received);
	}
	rawinfo("=================== statistics ends\n");
}

static void be_nobody(void)
{
	struct passwd *pw;

	if (getuid() != 0) {
		return;
	}
	pw = getpwnam("nobody");
	if (!pw) {
		error("getpwnam(\"nobody\"): %s\n", strerror(errno));
		return;
	}
	if (setgid(pw->pw_gid) < 0) {
		error("setgid: %s\n", strerror(errno));
		return;
	}
	if (setuid(pw->pw_uid) < 0) {
		error("setuid: %s\n", strerror(errno));
		return;
	}
}

int main(int argc, char *argv[])
{
	int opt;
	int udpinited = 0;
	char *endptr;
	struct tcpsock *tcpsock;

	signal(SIGUSR1, SIG_IGN);
	progname = basename(argv[0]);

	uloop_init();
	/* parse options */
	while ((opt = getopt(argc, argv, "s:l:t:T:qh")) != -1) {
		switch (opt) {
		case 's':
			if (ntcpsocks >= NSERVERS) {
				error("more than %d upstream DNS servers is not allowed.\n", NSERVERS);
				exit(EXIT_FAILURE);
			}
			tcpsock = &tcpsocks[ntcpsocks];
			if (!init_tcpsock(tcpsock, optarg)) {
				ntcpsocks += 1;
			}
			break;
		case 'l':
			if (udpinited) {
				error("multiple -l options are not allowed.\n");
				exit(EXIT_FAILURE);
			}
			init_udpsock(optarg);
			udpinited = 1;
			break;
		case 't':
			max_reconnect_delay = strtoul(optarg, &endptr, 10);
			if (*endptr) {
				error("invalid reconnect delay value: -t %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			max_reconnect_delay *= 1000;
			break;
		case 'T':
			tcp_shoddy_threshold = strtoul(optarg, &endptr, 10);
			if (*endptr) {
				error("invalid service delay value: -T %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			tcp_shoddy_threshold *= SEC2USEC;
			break;
		case 'q':
			quiet = 1;
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (!udpinited) {
		usage();
		exit(EXIT_FAILURE);
	}
	if (ntcpsocks <= 0) {
		error("no usable TCP server.\n");
		exit(EXIT_FAILURE);
	}
	if (signal(SIGUSR1, cb_sighup) == SIG_ERR) {
		error("signal(SIGUSR1) failed.\n");
		exit(EXIT_FAILURE);
	}
	be_nobody();

	info("start serving!\n");
	uloop_run();
	uloop_done();
	return 0;
}


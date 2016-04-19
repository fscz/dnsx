/*
 *  The Tor TCP DNS Daemon
 *
 *  Copyright (c) Collin R. Mulliner <collin(AT)mulliner.org>
 *  Copyright (c) 2010, The Tor Project, Inc.
 *
 */

// Update this version upon release
#define DNSX_VERSION "1.0"

#define NO_RETURN __attribute__ ((__noreturn__))

#define DEBUG 0

// number of parallel connected tcp peers
#define MAX_PEERS 1
// request timeout
#define MAX_TIME 3 /* QUASIBUG 3 seconds is too short! */
// number of trys per request (not used so far)
#define MAX_TRY 1
// maximal number of nameservers
#define MAX_NAMESERVERS 32
// request queue size (use a prime number for hashing)
#define MAX_REQUESTS 499
// 199, 1009
// max line size for configuration processing
#define MAX_LINE_SIZE 1025

// Magic numbers
#define RECV_BUF_SIZE 1502

#define NOBODY 65534
#define NOGROUP 65534

#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_SERVER_PORT 53

#define DEFAULT_NAMESERVER_FILE "conf/dnsx.conf"
#define DEFAULT_CHROOT "/var/lib/dnsx"
#define DEFAULT_TSOCKS_CONF "conf/tsocks.conf"

#define HELP_STR ""\
    "syntax: dnsx [bpfPCcdlhV]\n"\
    "\t-b\t<server ip>\tserver IP to bind\n"\
    "\t-p\t<server port>\tserver port to bind\n"\
    "\t-f\t<nameservers>\tfilename to read nameserver IP(s) from\n"\
    "\t-P\t<PID file>\tfile to store process ID - pre-chroot\n"\
    "\t-C\t<chroot dir>\tchroot(2) to <chroot dir>\n"\
    "\t-c\t\t\tDON'T chroot(2) to /var/lib/dnsx\n"\
    "\t-d\t\t\tbecome a daemon\n"\
    "\t-t\t\t\tpath to tsocks.conf file\n"\
    "\t-h\t\t\tprint this helpful text and exit\n"\
    "\t-V\t\t\tprint version and exit\n\n"\
    "export TSOCKS_CONF_FILE to point to config file inside the chroot\n"\
    "\n"

typedef enum {
    DEAD = 0,
    CONNECTING,
    CONNECTING2,
    CONNECTED
} CON_STATE;

typedef enum {
    WAITING = 0,
    SENT
} REQ_STATE;

struct request_t {
    struct sockaddr_in a; /* client’s IP/port */
    socklen_t al;
    unsigned char b[1502]; /**< request buffer */
    int bl; /**< bytes in request buffer */
    uint id; /**< dns request id */
    int rid; /**< real dns request id */
    REQ_STATE active; /**< 1=sent, 0=waiting for tcp to become connected */
    time_t timeout; /**< timeout of request */
};

struct peer_t
{
    struct sockaddr_in tcp;
    int tcp_fd;
    time_t timeout;
    CON_STATE con; /**< connection state 0=dead, 1=connecting..., 3=connected */
    unsigned char b[RECV_BUF_SIZE]; /**< receive buffer */
    int bl; /**< bytes in receive buffer */ // bl? Why don't we call this bytes_in_recv_buf or something meaningful?
};


// requests
int request_find(uint id);
struct in_addr ns_select(void);
int load_nameservers(char *filename);
void process_incoming_request(struct request_t *tmp);

// peers
void peer_connect(struct peer_t *p, struct in_addr ns);
int peer_connected(struct peer_t *p);
void peer_sendreq(struct peer_t *p, struct request_t *r);
int peer_readres(struct peer_t *p);
void peer_handleoutstanding(struct peer_t *p);
int peer_readres(struct peer_t *p);
void peer_mark_as_dead(struct peer_t *p);
struct peer_t *peer_select(void);

// main
void server_loop(void);

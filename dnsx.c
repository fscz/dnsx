/*
 *  DNSX Socks Proxying DNS Daemon
 *  Copyright (c) Fabian Schuetz <fscz@block0.de>
 *
 *  Based on ttdnsd
 *  Copyright (c) Collin R. Mulliner <collin(AT)mulliner.org>
 *  Copyright (c) 2010, The Tor Project, Inc.
 *
 *  http://www.mulliner.org/collin/ttdnsd.php
 *  https://www.torproject.org/ttdnsd/
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <limits.h>
#include "dnsx.h"


static struct in_addr *nameservers;              
static unsigned int num_nameservers;             

static struct peer_t peers[MAX_PEERS];           
static struct request_t requests[MAX_REQUESTS];  
static int server_fd;

static const char* TCP = "tcp";
static const char* UDP = "udp";
static const char* IN = "<-";
static const char* OUT = "->";
static const char* DROP_IN = "_<";
static const char* DROP_OUT = ">_";

#define PEER_IP(p) inet_ntoa(p->tcp.sin_addr)
#define PEER_PORT(p) ntohs(p->tcp.sin_port)

#define REQ_IP(r) inet_ntoa(r->a.sin_addr)
#define REQ_PORT(r) ntohs(r->a.sin_port)


////////////////////////////////////////////////////////////////////////////////
////////// PROGRAM/CONFIG/LOGGING
//////////
static void log_packet(const int id, const char* proto, const char* direction,
                       const char* ip, const int port) {  
  printf("[%d] %s %s %s:%d\n", id, proto, direction, ip, port);
}

static void load_nameservers_or_die(char *filename) {
  FILE *fp;
  char line[MAX_LINE_SIZE] = {0};
  unsigned long int ns;
  char *eolp;
  num_nameservers = 0;


  if (!(fp = fopen(filename, "r"))) {
    printf("cannot open nameserver file %s\n", filename);
    exit(1);
  }    
    
  if (!(nameservers = malloc(sizeof(nameservers[0]) * MAX_NAMESERVERS))) {
    fclose(fp);        
    exit(1);
  }

  while (fgets(line, MAX_LINE_SIZE, fp)) {
    if (line[0] == '#' || line[0] == '\n' || line[0] == ' ') continue;
    if ((eolp = strrchr(line, '\n')) != NULL){
      *eolp = 0;
    }
    if (strstr(line, "192.168.") == line) continue;
    if (strstr(line, "172.16.") == line) continue;
    if (strstr(line, "127.") == line) continue;
    if (strstr(line, "10.") == line) continue;
    if (inet_pton(AF_INET, line, &ns)) {
      if (num_nameservers >= MAX_NAMESERVERS) {
        printf("Loaded maximum [%d] nameservers.\n", num_nameservers);
        break;
      }
      nameservers[num_nameservers].s_addr = ns;
      num_nameservers++;
      printf("Loaded %s as a nameserver.\n", line);
    }
    else {
      printf("Not a valid IPv4 address: %s\n", line);
    }
  }
  fclose(fp);
  nameservers = realloc(nameservers, sizeof(unsigned long int) * num_nameservers);
}

static void bind_or_die(char* server_ip, int server_port) {  
  struct sockaddr_in udp;
  
  if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    printf("cannot create UDP socket\n");
    exit(1);
  }
  bzero((char*)&udp, sizeof(struct sockaddr_in));
  udp.sin_family = AF_INET;
  udp.sin_port = htons(server_port);
  if (!inet_aton(server_ip, (struct in_addr*)&udp.sin_addr)) {
    printf("cannot bind to ipv4 address: %s\n", server_ip);
    exit(1);
  }

  if (bind(server_fd, (struct sockaddr*)&udp, sizeof(struct sockaddr_in)) < 0) {
    printf("cannot bind to %s:%d\n", server_ip, server_port);
    close(server_fd);
    exit(1);
  }

}

static void chroot_or_die(const char* chroot_dir) {
  
  if (chdir(chroot_dir)) {
    printf("cannot chdir to %s, exit\n", chroot_dir);
    exit(1);
  }
  if (chroot(chroot_dir)) {
    printf("cannot chroot to %s, exit\n", chroot_dir);
    exit(1);
  }
  char* env_ptr = getenv("TSOCKS_CONF_FILE");
  
  if (access(env_ptr, R_OK) != 0) {
    printf("chroot=%s, unable to access tsocks config at %s, exit\n", chroot_dir, env_ptr);
    exit(1);
  }
  
}

static void configure_tsocks(char* tsocks_conf) {

  if (!tsocks_conf) {
    char buffer[PATH_MAX];
    char* env_ptr = getenv("TSOCKS_CONF_FILE");
    if (!env_ptr) {
      strncpy(buffer, DEFAULT_TSOCKS_CONF, (sizeof(buffer)-1));
    } else {
      strncpy(buffer, env_ptr, (sizeof(tsocks_conf)-1));
    }
    buffer[PATH_MAX-1] = '\0';
    setenv("TSOCKS_CONF_FILE", buffer, 1);
  } else {
    setenv("TSOCKS_CONF_FILE", tsocks_conf, 1);
  }
}

static void drop_priviliges() {
  int r = setgid(NOGROUP);
  if (r != 0) {
    printf("setgid failed!\n");
    exit(1);
  }
  r = setuid(NOBODY);
  if (r != 0) {
    printf("setuid failed!\n");
    exit(1);
  }
}

static void daemonize_or_die() {
  if (fork()) exit(0);
  setsid(); // Safe?
}

////////////////////////////////////////////////////////////////////////////////
////////// REQUESTS
//////////

/* Selects a random nameserver from the pool and returns the number. */
struct in_addr ns_select(void) {
  // This could use a real bit of randomness, I suspect
  return nameservers[(rand()>>16) % num_nameservers];
}

/* Return a positive positional number or -1 for unfound entries. */
int request_find(uint id) {
  uint pos = id % MAX_REQUESTS;

  for (;;) {
    if (requests[pos].id == id) {
      return pos;
    }
    else {
      pos++;
      pos %= MAX_REQUESTS;
      if (pos == (id % MAX_REQUESTS)) {
        return -1;
      }
    }
  }
}


/* Return 0 for a request that is pending or if all slots are full, otherwise
   return the value of peer_sendreq or peer_connect respectively... */
static void request_add(struct request_t *r) {
  uint pos = r->id % MAX_REQUESTS; // XXX r->id is unchecked
  struct peer_t *dst_peer;
  unsigned short int *ul;
  time_t ct = time(NULL);
  struct request_t *req_in_table = 0;

  for (;;) {
    if (requests[pos].id == 0) {
      // this one is unused, take it
      req_in_table = &requests[pos];
      break;
    }
    else {
      if (requests[pos].id == r->id) {
        if (memcmp((char*)&r->a, (char*)&requests[pos].a, sizeof(r->a)) == 0) {
          // a request for the same id and url already exists
          // do not process the new request
          return;
        }
        else {
          // ids are same but the queried urls are different.
          // this is weird. we rather drop the package before
          // we do some black magic that blows up on us.
          // one failed ns request is not that bad.
          // clients usually repeat them anyways.
          /*
          do {
            r->id = ((rand()>>16) % 0xffff);
          } while (r->id < 1);
          pos = r->id % MAX_REQUESTS;
          //printf("NATing id (id was %d now is %d)\n", r->rid, r->id);
          continue;
          */
          log_packet(r->id, DROP_IN, UDP, REQ_IP(r), REQ_PORT(r));
          return;
        }
      }
      else if ((requests[pos].timeout + MAX_TIME) > ct) {
        // request timed out, take it               
        req_in_table = &requests[pos];
        break;
      }
      else {
        pos++;
        pos %= MAX_REQUESTS;
        if (pos == (r->id % MAX_REQUESTS)) {
          // we are at our capacities. drop the request
          log_packet(r->id, DROP_IN, UDP, REQ_IP(r), REQ_PORT(r));
          return;
        }
      }
    }
  }

  r->timeout = time(NULL); /* REFACTOR not ct? sloppy */

  // update id
  ul = (unsigned short int*)(r->b + 2);
  *ul = htons(r->id);   

  if ( req_in_table == NULL ) {
    return;
  } else {
    memcpy((char*)req_in_table, (char*)r, sizeof(*req_in_table));
  }
  
  dst_peer = peer_select();

  if (dst_peer->con == CONNECTED) {
    peer_sendreq(dst_peer, req_in_table);
  }
  else if (dst_peer->con != CONNECTING) {
    // The request will be sent by peer_handleoutstanding when the
    // connection is established. Actually (see QUASIBUG notice
    // earlier) when *any* connection is established.
    peer_connect(dst_peer, ns_select());
  } 
}

void process_incoming_request(struct request_t *tmp) {
  // get request id
  unsigned short int *ul = (unsigned short int*) (tmp->b + 2);
  tmp->rid = tmp->id = ntohs(*ul);
  // get request length
  ul = (unsigned short int*)tmp->b;
  *ul = htons(tmp->bl);


  log_packet(tmp->rid, UDP, IN, REQ_IP(tmp), REQ_PORT(tmp));

  request_add(tmp); // This should be checked; we're currently ignoring important returns.
}

////////////////////////////////////////////////////////////////////////////////
////////// PEERS
//////////
void peer_connect(struct peer_t *p, struct in_addr ns) {
  int socket_opt_val = 1;
  int cs;

  if (p->con == CONNECTING || p->con == CONNECTING2) {
    printf("It appears that peer %s is already CONNECTING\n",  PEER_IP(p));
    return;
  }


  if ((p->tcp_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("cannot create TCP socket\n");
    peer_mark_as_dead(p);
    return;
  }

    
  if (setsockopt(p->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &socket_opt_val, sizeof(int))) {
    printf("Setting SO_REUSEADDR failed\n");
    peer_mark_as_dead(p);
    return;
  }

  p->tcp.sin_family = AF_INET;

  // This should not be hardcoded to a magic number; per ns port data structure changes required
  p->tcp.sin_port = htons(53);

  p->tcp.sin_addr = ns;

  cs = connect(p->tcp_fd, (struct sockaddr*)&p->tcp, sizeof(struct sockaddr_in));

  if (cs != 0 && errno != EINPROGRESS) {
    printf("connect status not in progress after connect()\n");
    peer_mark_as_dead(p);
    return;
  }

  // We should be in non-blocking mode now
  p->bl = 0;
  p->con = CONNECTING;

}

/* Returns 1 upon non-blocking connection; 0 upon serious error */
int peer_connected(struct peer_t *p) {
  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(p->tcp_fd, &wfds);

  struct timeval timeout = {
    .tv_sec = 1,
    .tv_usec = 0
  };

  char error[30];
  socklen_t len = 30;

  // check if the socket is connected by selecting for writing
  // and see if we get an error. if not, we consider this socket
  // connected.
  if ( 0 == select(p->tcp_fd, NULL, &wfds, NULL, &timeout) 
       && 0 == getsockopt(p->tcp_fd, SOL_SOCKET, SO_ERROR, error, &len) ) {
    p->con = CONNECTED;
    return 1;
  } 

  printf("Connecting to nameserver [%s] failed. Is Tor running?\n", PEER_IP(p));
  close(p->tcp_fd);
  p->tcp_fd = -1;
  p->con = DEAD;

  return 0;
}

void peer_mark_as_dead(struct peer_t *p) {
  close(p->tcp_fd);
  p->tcp_fd = -1;
  p->con = DEAD;    
}

/* Returns 1 upon sent request; 0 upon serious error and 2 upon disconnect */
void peer_sendreq(struct peer_t *p, struct request_t *r) {
  int ret;
  r->active = SENT;        /* BUG: even if the write below fails? */

  /* QUASIBUG Busy-waiting on the network buffer to free up some
     space is not acceptable; at best, it wastes CPU; at worst, it
     hangs the daemon until the TCP timeout informs it that its
     connection to Tor has timed out. (Although that’s an unlikely
     failure mode.) */
  /* BUG: what if write() doesn't write all the data? */
  /* This is writing data to the remote DNS server over Tor with TCP */
  while ((ret = write(p->tcp_fd, r->b, (r->bl + 2))) < 0 && errno == EAGAIN);    

  if (ret == 0) {
    peer_mark_as_dead(p);
    log_packet(r->id, TCP, DROP_OUT, PEER_IP(p), PEER_PORT(p));
  }

  log_packet(r->id, TCP, OUT, PEER_IP(p), PEER_PORT(p));   
}

/* Returns -1 on error, returns 1 on something, returns 2 on something, returns 3 on disconnect. */
/* XXX This function needs a really serious re-write/audit/etc. */
int peer_readres(struct peer_t *p) {
  struct request_t *r;
  int ret;
  unsigned short int *ul;
  int id;
  int req;
  unsigned short int *l;
  int len;

  l = (unsigned short int*)p->b;

  /* BUG: we’re reading on a TCP socket here, so we could in theory
     get a partial response. Using TCP puts the onus on the user
     program (i.e. this code) to buffer bytes until we have a
     parseable response. This probably won’t happen very often in
     practice because even with DF, the path MTU is unlikely to be
     smaller than the DNS response. But it could happen.  And then
     we fall into the `processanswer` code below without having the
     whole answer. */
  /* This is reading data from Tor over TCP */
  while ((ret = read(p->tcp_fd, (p->b + p->bl), (RECV_BUF_SIZE - p->bl))) < 0 && errno == EAGAIN);

  if (ret == 0) {
    peer_mark_as_dead(p);
    return 3;
  }

  p->bl += ret;

  // we have an answer
  // get answer from receive buffer
  do {

    if (p->bl < 2) {
      return 2;
    }
    else {
      len = ntohs(*l);

      if ((len + 2) > p->bl)
        return 2;
    }

    ul = (unsigned short int*)(p->b + 2);
    id = ntohs(*ul);
    log_packet(id, TCP, IN, PEER_IP(p), PEER_PORT(p));

    if ((req = request_find(id)) == -1) {
      memmove(p->b, (p->b + len + 2), (p->bl - len - 2));
      p->bl -= len + 2;
      return 0;
    }
    r = &requests[req];

    // write back real id
    *ul = htons(r->rid);

    // Remove the AD flag from the reply if it has one. Because we might be
    // answering requests to 127.0.0.1, the client might consider us
    // trusted. While trusted, we shouldn't indicate that data is DNSSEC
    // valid when we haven't checked it.
    // See http://tools.ietf.org/html/rfc2535#section-6.1
    if (len >= 6)
      p->b[5] &= 0xdf;

    /* This is where we send the answer over UDP to the client */
    r->a.sin_family = AF_INET;
    log_packet(id, UDP, OUT, REQ_IP(r), REQ_PORT(r));
    while (sendto(server_fd, (p->b + 2), len, 0, (struct sockaddr*)&r->a, sizeof(struct sockaddr_in)) < 0 && errno == EAGAIN);


    memmove(p->b, p->b + len +2, p->bl - len - 2);
    p->bl -= len + 2;

    // mark as handled/unused
    r->id = 0;

  } while (p->bl > 0);

  return 1;
}

/* Handles outstanding peer requests and does not return anything. */
void peer_handleoutstanding(struct peer_t *p) {
  int i;

  /* QUASIBUG It doesn’t make sense that sometimes `request_add`
     will queue up a request to be sent to nameserver #2 when a
     connection is already open to nameserver #1, but then send that
     request to nameserver #3 if nameserver #3 happens to finish
     opening its connection before nameserver #2. */

  for (i = 0; i < MAX_REQUESTS; i++) {
    struct request_t *r = &requests[i];
    if (r->id != 0 && r->active == WAITING) {
      peer_sendreq(p, r);
    }
  }
}

struct peer_t *peer_select(void) {
  return &peers[0];
}




////////////////////////////////////////////////////////////////////////////////
////////// SERVER LOOP
//////////
NO_RETURN void server_loop(void) {
  
  struct pollfd pfd[MAX_PEERS+1];
  int poll2peers[MAX_PEERS];
  int fr;
  int i;
  int pfd_num;

  for (i = 0; i < MAX_PEERS; i++) {
    peers[i].tcp_fd = -1;
    poll2peers[i] = -1;
    peers[i].con = DEAD;
  }
  bzero((char*)requests, sizeof(requests));

  for (;;) {
    // populate poll array
    for (pfd_num = 1, i = 0; i < MAX_PEERS; i++) {  
      if (peers[i].tcp_fd != -1) {
        pfd[pfd_num].fd = peers[i].tcp_fd;
        switch (peers[i].con) {
        case CONNECTED:
          pfd[pfd_num].events = POLLIN|POLLPRI;
          break;
        case DEAD:
          pfd[pfd_num].events = POLLOUT|POLLERR;
          break;
        case CONNECTING:
          pfd[pfd_num].events = POLLOUT|POLLERR;
          break;
        case CONNECTING2:
          pfd[pfd_num].events = POLLOUT|POLLERR;
          break;
        default:
          pfd[pfd_num].events = POLLOUT|POLLERR;
          break;
        }
        poll2peers[pfd_num-1] = i;
        pfd_num++;
      }
    }

    pfd[0].fd = server_fd;
    pfd[0].events = POLLIN|POLLPRI;

    fr = poll(pfd, pfd_num, -1);



    // handle tcp connections
    for (i = 1; i < pfd_num; i++) {

      uint peer = poll2peers[i-1];
      struct peer_t *p = &peers[peer];


      if ((pfd[i].revents & POLLHUP) == POLLHUP) {
        peer_mark_as_dead(p);
        continue;
      }

      if (pfd[i].fd != -1 && (
                              (pfd[i].revents & POLLIN) == POLLIN 
                              || (pfd[i].revents & POLLPRI) == POLLPRI 
                              || (pfd[i].revents & POLLOUT) == POLLOUT 
                              || (pfd[i].revents & POLLERR) == POLLERR)) {


        if (peer > MAX_PEERS) {
          printf("error: too many peers.");
        } else {
          switch (p->con) {
          case CONNECTED:
            peer_readres(p);
            break;
          case CONNECTING:
          case CONNECTING2:
            if (peer_connected(p)) {
              peer_handleoutstanding(p);
            }
            break;
          case DEAD:
          default:
            printf("error: peer %s state: %i\n", PEER_IP(p), p->con);
            break;
          }
        }
      } 
    }

    // handle port 53
    if ((pfd[0].revents & POLLIN) == POLLIN || (pfd[0].revents & POLLPRI) == POLLPRI) {

      struct request_t tmp;
      memset((char*)&tmp, 0, sizeof(struct request_t)); // bzero
      tmp.al = sizeof(struct sockaddr_in);

      tmp.bl = recvfrom(server_fd, tmp.b+2, RECV_BUF_SIZE-2, 0, 
                        (struct sockaddr*)&tmp.a, &tmp.al);
      if (tmp.bl < 0) {
        printf("error: recv udp fd");
      } else {
        process_incoming_request(&tmp);
      }
    }        
  }
}


////////////////////////////////////////////////////////////////////////////////
////////// MAIN
//////////
int main(int argc, char **argv) {
  int opt;
  int daemonize = 0;
  int do_chroot = 0;
  int do_drop_priviliges = 0;

  char nameserver_file[250] = {DEFAULT_NAMESERVER_FILE};
  char server_ip[250] = {DEFAULT_SERVER_IP};
  int server_port = DEFAULT_SERVER_PORT;
  char chroot_dir[PATH_MAX] = {DEFAULT_CHROOT};
  char* tsocks_dummy = NULL;
  char tsocks_conf[PATH_MAX];

  while ((opt = getopt(argc, argv, "VhdcC:b:f:p:P:t:")) != EOF) {
    switch (opt) {
    case 't':
      strncpy(tsocks_conf, optarg, sizeof(tsocks_conf)-1);
      tsocks_dummy = tsocks_conf;
      break;
      // daemonize
    case 'd':
      daemonize = 1;
      break;
      // DON'T chroot
    case 'c':
      do_chroot = 1;
      break;
      // Chroot directory
    case 'C':
      strncpy(chroot_dir, optarg, sizeof(chroot_dir)-1);
      break;     
      // config file
    case 'f':
      strncpy(nameserver_file, optarg, sizeof(nameserver_file)-1);
      break;
      // IP
    case 'b':
      strncpy(server_ip, optarg, sizeof(server_ip)-1);
      break;
     // PORT
    case 'p':
      server_port = atoi(optarg);
      if (server_port < 1) server_port = DEFAULT_SERVER_PORT;
      break;
     // drop priviliges
    case 'P':
      do_drop_priviliges = 1;
      break;
      // print version and exit
    case 'V':
      printf("dnsx version %s\n", DNSX_VERSION);
      exit(0);
      // help
    case 'h':
    default:
      printf("%s", HELP_STR);
      exit(0);
      break;
    }
  }

  srand(time(NULL)); // This should use OpenSSL in the future

  // be root or die
  if ( (server_port == DEFAULT_SERVER_PORT || do_chroot == 1) && getuid() != 0 ) {
    printf("dnsx must run as root to bind to port 53 and chroot(2)\n");
    exit(1);
  }    

  load_nameservers_or_die(nameserver_file);

  // maybe become a daemon
  if (daemonize) {
    daemonize_or_die();
  }

  // configure tsocks
  configure_tsocks(tsocks_dummy);  

  // maybe chroot
  if (do_chroot) {
    chroot_or_die(chroot_dir);    
  }
  
  // bind to udp port 53
  bind_or_die(server_ip, server_port);

  // maybe drop privileges    
  if (do_drop_priviliges) {
    drop_priviliges();
  }

  // go into main loop
  printf("starting server at: %s:%d\n", server_ip, server_port);
  server_loop();
}

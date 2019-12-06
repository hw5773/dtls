#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/types.h>
#ifndef _WIN32
#include <netinet/in.h>
#ifdef _XOPEN_SOURCE_EXTENDED
  #include <arpa/inet.h>
#endif
#include <sys/socket.h>
#endif
#include <sys/stat.h>

#include <pthread.h>
#include <limits.h>
#include <getopt.h>

#include <event.h>
#include <defines.h>
#include <debug.h>
#include "setting.h"

typedef struct info_st
{
  SSL_CTX *ctx;
  const char *domain;
  int port;
} info_t;

void connect_to_server(void *data, unsigned char *buf, int *len);
int open_listener(int port);
int open_connection(const char *domain, int port);
SSL_CTX* init_client_ctx(void);
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void load_ecdh_params(SSL_CTX *ctx);
int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content,
		uint32_t clen, uint8_t *msg, uint32_t *mlen);
int http_parse_response(uint8_t *msg, uint32_t mlen);
static int char_to_int(uint8_t *str, uint32_t slen);
static void udp_cb(const int fd, short int event, void *arg);

int 
usage(const char *pname)
{
  emsg(">> Usage: %s -d <domain> -p <port> -l <log file name>", pname);
  emsg(">> Example: %s -d www.alice.com -p 5555 -l 5556", pname);
  exit(1);
}

int 
main(int argc, char *argv[])
{   
	int i, rc, num_of_threads, fd;
  int c, cport, lport;
  const char *pname;
  const char *domain;
  const char *lname;
  SSL_CTX *ctx;
  info_t *info;

  struct event_base *base;
  struct event udp_event;
  
  pname = argv[0];
  domain = DEFAULT_DOMAIN_NAME;
  lport = DEFAULT_LISTEN_PORT_NUMBER;
  cport = DEFAULT_CONNECT_PORT_NUMBER;
  num_of_threads = DEFAULT_NUM_THREADS;
  lname = NULL;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"domain", required_argument, 0, 'd'},
      {"port", required_argument, 0, 'p'}, 
      {"listen-port", required_argument, 0, 'l'},
      {"threads", required_argument, 0, 't'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "d:p:l:t:0", long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
    {
      case 'l':
        lport = atoi(optarg);
        break;
      case 'd':
        domain = optarg;
        break;
      case 'p':
        cport = atoi(optarg);
        break;
      case 't':
        num_of_threads = atoi(optarg);
        break;
      default:
        usage(pname);
    }
  }

  imsg("Domain: %s", domain);
  imsg("Listen Port: %d", lport);
  imsg("Connection Port: %d", cport);
  imsg("Number of Threads: %d", num_of_threads);

  SSL_library_init();
  OpenSSL_add_all_algorithms();

	ctx = init_client_ctx();
	load_ecdh_params(ctx);
  info = (info_t *)malloc(sizeof(info_t));
  memset(info, 0x0, sizeof(info_t));
  info->ctx = ctx;
  info->domain = domain;
  info->port = cport;

  fd = open_listener(lport);
  base = event_init();
  event_set(&udp_event, fd, EV_READ|EV_PERSIST, udp_cb, info);
  event_add(&udp_event, 0);
  event_dispatch();

	SSL_CTX_free(ctx); /* release context */

	return 0;
}

void connect_to_server(void *data, unsigned char *buf, int *len)
{	
  fstart("data: %p, buf: %p, len: %p", data, buf, len);
  const char *domain;
	int i, port, server, ret;
	SSL *ssl;
	SSL_SESSION *session = NULL;
  info_t *info;
  BIO *b;
  
  info = (info_t *)data;
  domain = info->domain;
  port = info->port;
  b = BIO_new(BIO_s_mem());
  
	server = open_connection(domain, port);
  ssl = SSL_new(info->ctx);   
  SSL_set_fd(ssl, server);
  SSL_set_tlsext_host_name(ssl, domain);

	if (session != NULL)
		SSL_set_session(ssl, session);

	emsg("Set server name: %s", domain);

	imsg("PROGRESS: DTLS Handshake Start");

	if ((ret = SSL_connect(ssl)) < 0) {
		emsg("ret after SSL_connect: %d", ret);
		ERR_print_errors_fp(stderr);
		goto err;
	} else {
    imsg("Connected with %s\n", SSL_get_cipher(ssl));
    SSL_shutdown(ssl);
    session = SSL_get_session(ssl);
    if (session)
    {
      imsg("Acquire the SSL session");
      PEM_write_bio_SSL_SESSION(b, session);
      *len = BIO_read(b, buf, BUF_SIZE);
      imsg("Length of SSL_SESSION: %d", *len);
    }
    else
    {
      imsg("Cannot acquire the SSL session");
      abort();
    }
    SSL_free(ssl);
    ssl = NULL;
    close(server);
  }
    
err: 
  if (!session)
		SSL_SESSION_free(session);
	if (!ssl) {
		SSL_free(ssl);
		ssl = NULL;
	}
	if (server != -1)
		close(server);

  ffinish();
}

static void
udp_cb(const int fd, short int event, void *user_data)
{
  fstart("fd: %d, event: %d, user_data: %p", fd, event, user_data);
  int i, rc, rlen, wlen, ret;
  info_t *info;
  unsigned char rbuf[BUF_SIZE] = {0, };
  unsigned char wbuf[BUF_SIZE] = {0, };
  SSL_SESSION *session;
  struct sockaddr_in sin;
  socklen_t sz;

  info = (info_t *)user_data;
  session = NULL;

  memset(&sin, 0, sizeof(sin));
  rlen = recvfrom(fd, &rbuf, BUF_SIZE, MSG_WAITALL, (struct sockaddr *) &sin, &sz);
  dmsg("recvfrom: fd: %d, sin: %p, sz: %d", fd, &sin, sz);

  if (rlen < 0)
  {
    emsg("recvfrom error");
    event_loopbreak();
  }
  dmsg("rlen: %d, sz: %u", rlen, sz);
  wlen = sendto(fd, "thanks!", 7, MSG_CONFIRM, (struct sockaddr *)&sin, sz);
  dmsg("[TEST] wlen: %d", wlen);
  perror("Test");

  if (rlen > 0)
  {
    imsg("Received message: %s", rbuf);
    connect_to_server(info, wbuf, &wlen);
    dmsg("Length of the SSL Session: %d bytes", wlen);

    if (wlen > 0)
    {
      dmsg("sendto: fd: %d, wbuf: %p, wlen: %d, sin: %p, sizeof(sin): %lu, sz: %d", fd, wbuf, wlen, &sin, sizeof(struct sockaddr_in), sz);
      if (sendto(fd, wbuf, wlen, MSG_CONFIRM, (struct sockaddr *)&sin, sz) < 0)
      {
        emsg("sendto error: %d", errno);
        perror("sendto");
        event_loopbreak();
      } 
    }
  }

  ffinish();
}

int 
open_listener(int port)
{
  fstart("port: %d", port);
  int sock, option;
  struct sockaddr_in sin;

  option = 1;

  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("socket creation failed");
    exit(1);
  }

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(port);

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *)&option, sizeof(option)) < 0)
  {
    emsg("setsockopt error");
  }

  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
  {
    emsg("bind error");
    exit(1);
  }

  ffinish("sock: %d", sock);
  return sock;
}

int 
open_connection(const char *domain, int port)
{
  fstart("domain: %s, port: %d", domain, port);
  int sd;
  struct hostent *host;
  struct sockaddr_in addr;
            
  if ( (host = gethostbyname(domain)) == NULL )
  {
    perror(domain);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_DGRAM, 0);
  bzero(&addr, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(host->h_addr);

  if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
  {
    close(sd);
    perror(domain);
    abort();
  }
  
  ffinish("sd: %d", sd);
  return sd;
}

SSL_CTX* init_client_ctx(void) 
{
  fstart();
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings(); /* Bring in and register error messages */
	method = (SSL_METHOD *) DTLSv1_2_client_method(); /* Create new client-method instance */
	ctx = SSL_CTX_new(method); /* Create new context */

	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		abort();
	}

  ffinish("ctx: %p", ctx);
	return ctx;
}

void load_ecdh_params(SSL_CTX *ctx) {
  fstart("ctx: %p", ctx);
	EC_KEY *ecdh;
	ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	if (!ecdh)
		perror("Couldn't load the ec key");

	if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
		perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
  ffinish();
}

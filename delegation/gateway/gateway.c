#include <stdio.h>
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
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/opensslv.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>

#include <defines.h>
#include <debug.h>
#include "setting.h"

#define DELIMITER "\r\n"
#define DELIMITER_LEN 2

typedef struct info_st
{
  SSL_CTX *ctx;
  const char *domain;
  int port;
} info_t;

SSL_CTX *ctx;

void *run(void *data);
int open_listener(int port);
int open_connection(const char *domain, int port);
SSL_CTX* init_client_ctx(void);
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void load_ecdh_params(SSL_CTX *ctx);
int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content,
		uint32_t clen, uint8_t *msg, uint32_t *mlen);
int http_parse_response(uint8_t *msg, uint32_t mlen);
static int char_to_int(uint8_t *str, uint32_t slen);
static void udp_cb(const int fd, short event, void *arg);
pthread_t thread[num_of_threads];
pthread_attr_t attr;
void *status;

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
  lport = 
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
        port = atoi(optarg);
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

  initialization();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  fd = open_listener(lport);
  base = event_init();
  info = (info_t *)malloc(sizeof(info_t));
  memset(info, 0x0, sizeof(info_t));

  SSL_library_init();
  OpenSSL_add_all_algorithms();
	ctx = init_client_ctx();
	load_ecdh_params(ctx);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  info->ctx = ctx;
  info->domain = domain;
  info->port = cport;

  event_set(&udp_event, fd, EV_READ|EV_PERSIST, udp_cb, info);
  event_add(&udp_event, 0);
  event_dispatch();

	for (i = 0; i < num_of_threads; i++) {
		rc = pthread_create(&thread[i], &attr, run, &info);

		if (rc) {
			emsg("return code from pthread_create: %d\n", rc);
			return 1;
		}
	}

	pthread_attr_destroy(&attr);

	for (i = 0; i < num_of_threads; i++) {
		rc = pthread_join(thread[i], &status);

		if (rc) {
			emsg("return code from pthread_join: %d\n", rc);
			return 1;
		}
	}

	SSL_CTX_free(ctx); /* release context */

	return 0;
}

void *run(void *data)
{	
  fstart("data: %p", data);
  const char *domain;
	int i, port, server, rcvd, sent, ret, dlen, clen, total = 0, offset = 0;
  unsigned char buf[BUF_SIZE];
	SSL *ssl;
	SSL_SESSION *session = NULL;
  SSL_SESSION *test = NULL;
	char request[BUF_SIZE];
	int rlen;
  info_t *info;
  BIO *b;
  
  info = (info_t *)data;
  domain = info->domain;
  port = info->port;
  b = BIO_new(BIO_s_mem());
  
	server = open_connection(domain, port);
  ssl = SSL_new(ctx);   
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
    }
    else
    {
      imsg("Cannot acquire the SSL session");
      abort();
    }
    SSL_free(ssl);
    ssl = NULL;
    close(server);
    
    test = PEM_read_bio_SSL_SESSION(b, NULL, NULL, NULL);
    if (test)
    {
      imsg("Succeed to read the SSL session");

    }
    else
    {
      imsg("Failed to read the SSL session");
      abort();
    }

    server = open_connection(domain, port);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);
    SSL_set_tlsext_host_name(ssl, domain);

    if (session)
    {
      imsg("Set the SSL session to the SSL context");
      SSL_set_session(ssl, session);
    }

    if ((ret = SSL_connect(ssl)) < 0)
    {
      emsg("Failed to connect: %d", ret);
      ERR_print_errors_fp(stderr);
      goto err;
    }
    imsg("Succeed to resume the SSL session");
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
	return NULL;
}

static void
udp_cb(const int fd, short event, void *user_data)
{

}

int 
open_listener(int port)
{
  int sock;
  struct sockaddr_in sin;
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(port);

  if (bind(sock, (struct sockaddr *)&sin, sizeof(sin)))
  {
    emsg("bind error");
    exit(1);
  }

  return sock;
}

int 
open_connection(const char *domain, int port)
{
  fstart("domain: %s, port: %d", domain, port);
  int sd, ret, sndbuf, rcvbuf, optlen;
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
  
  sndbuf = 81920000;
  ret = setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

  if (ret < 0)
    printf("Error setsockopt: sndbuf\n");

  rcvbuf = 81920000;
  ret = setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

  if (ret < 0)
    printf("Error setsockopt: rcvbuf\n");

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

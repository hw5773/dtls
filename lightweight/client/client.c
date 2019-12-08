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
#include "../common/prince.h"

typedef struct info_st
{
  const char *domain;
  int port;
} info_t;

SSL_CTX *ctx;
static clock_t start = 0;
static clock_t end = 0;

void *run(void *data);
int open_connection(const char *domain, int port, struct sockaddr_in *addr);
SSL_CTX* init_client_ctx(const char *cert, const char *key);
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void load_ecdh_params(SSL_CTX *ctx);
int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content,
		uint32_t clen, uint8_t *msg, uint32_t *mlen);
int http_parse_response(uint8_t *msg, uint32_t mlen);
static int char_to_int(uint8_t *str, uint32_t slen);

int 
usage(const char *pname)
{
  emsg(">> Usage: %s -d <domain> -p <port> -l <log file name>", pname);
  emsg(">> Example: %s -d www.alice.com -p 5555 -l log", pname);
  exit(1);
}

int 
main(int argc, char *argv[])
{   
	int i, rc, num_of_threads;
  int c, port;
  const char *pname;
  const char *domain;
  const char *lname;
  const char *cert;
  const char *key;
  info_t info;
  
  pname = argv[0];
  domain = DEFAULT_DOMAIN_NAME;
  port = DEFAULT_PORT_NUMBER;
  num_of_threads = DEFAULT_NUM_THREADS;
  cert = DEFAULT_CLIENT_CERT_PATH;
  key = DEFAULT_CLIENT_KEY_PATH;
  lname = NULL;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"domain", required_argument, 0, 'd'},
      {"port", required_argument, 0, 'p'}, 
      {"log", required_argument, 0, 'l'},
      {"threads", required_argument, 0, 't'},
      {"cert", required_argument, 0, 'c'},
      {"key", required_argument, 0, 'k'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "d:p:l:t:c:k:0", long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
    {
      case 'l':
        lname = optarg;
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
      case 'c':
        cert = optarg;
        break;
      case 'k':
        key = optarg;
        break;
      default:
        usage(pname);
    }
  }

  imsg("Log File Name: %s", lname);
  imsg("Domain: %s", domain);
  imsg("Port: %d", port);
  imsg("Number of Threads: %d", num_of_threads);
  imsg("Certificate: %s", cert);
  imsg("Private Key: %s", key);

  info.domain = domain;
  info.port = port;

  init_prince();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

	pthread_t thread[num_of_threads];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

	ctx = init_client_ctx(cert, key);
	load_ecdh_params(ctx);

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
  struct sockaddr_in addr;
  socklen_t addr_len;
	SSL *ssl;
	SSL_SESSION *session = NULL;
	char request[BUF_SIZE];
	int rlen;
  info_t *info;
  
  info = (info_t *)data;
  domain = info->domain;
  port = info->port;
  
	server = open_connection(domain, port, &addr);

  ssl = SSL_new(ctx);   
  SSL_set_fd(ssl, server);
  SSL_set_tlsext_host_name(ssl, domain);

	if (session != NULL)
		SSL_set_session(ssl, session);

	emsg("Set server name: %s", domain);

	imsg("PROGRESS: DTLS Handshake Start");

  start = clock();
	if ((ret = SSL_connect(ssl)) < 0) {
		emsg("ret after SSL_connect: %d", ret);
		ERR_print_errors_fp(stderr);
		goto err;
	} else {
    end = clock();
    imsg("Connected with %s: %lf ms", SSL_get_cipher(ssl), ((double)(end - start) * 1000)/CLOCKS_PER_SEC );

    getsockname(server, (struct sockaddr *)&addr, &addr_len);
    port = ntohs(addr.sin_port);
    unsigned ciph[64];
    int ciph_len;
    prince_encrypt(SHARED_SECRET_KEY, 16, TEST_MESSAGE, strlen(TEST_MESSAGE), ciph, &ciph_len);
    if (sendto(server, ciph, ciph_len, 0, (struct sockaddr *)&addr, addr_len) < 0)
    {
      emsg("sendto error");
      goto err;
    }
    else
    {
      imsg("Succeed to send the message (%d bytes): %s", strlen(TEST_MESSAGE), TEST_MESSAGE);
    }
    SSL_shutdown(ssl);
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

int open_connection(const char *domain, int port, struct sockaddr_in *addr)
{
  fstart("domain: %s, port: %d", domain, port);
  int sd, ret, sndbuf, rcvbuf, optlen;
  struct hostent *host;
            
  if ( (host = gethostbyname(domain)) == NULL )
  {
    perror(domain);
    abort();
  }
    
  sd = socket(PF_INET, SOCK_DGRAM, 0);
  bzero(addr, sizeof(*addr));
  addr->sin_family = AF_INET;
  addr->sin_port = htons(port);
  addr->sin_addr.s_addr = *(long*)(host->h_addr);

  if ( connect(sd, (struct sockaddr*)addr, sizeof(*addr)) != 0 )
  {
    close(sd);
    perror(domain);
    abort();
  }
  
  ffinish("sd: %d", sd);
  return sd;
}

SSL_CTX* init_client_ctx(const char *cert, const char *key) 
{
  fstart();
	SSL_METHOD *method;
	SSL_CTX *ctx;
  EC_KEY *ecdh;

	SSL_load_error_strings(); /* Bring in and register error messages */
	method = (SSL_METHOD *) DTLSv1_2_client_method(); /* Create new client-method instance */
	ctx = SSL_CTX_new(method); /* Create new context */

  if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
  {
    emsg("SSL_CTX_use_certificate_file error");
    abort();
  }
  imsg("SSL_CTX_use_certificate_file success");

  if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
  {
    emsg("SSL_CTX_use_PrivateKey_file error");
    abort();
  }
  imsg("SSL_CTX_use_PrivateKey_file success");

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ecdh)
  {
    emsg("Set ECDH error");
    abort();
  }

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
  {
    emsg("SSL_CTX_set_tmp_ecdh error");
    abort();
  }
  imsg("Set ECDH success");

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

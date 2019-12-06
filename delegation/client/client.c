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
  const char *sdomain;
  int sport;
  const char *gdomain;
  int gport;
} info_t;

void *run(void *data);
int open_connection(const char *domain, int port, struct sockaddr_in *addr, socklen_t *sz);
SSL_CTX* init_client_ctx(void);
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void load_ecdh_params(SSL_CTX *ctx);
int http_make_request(uint8_t *domain, uint32_t dlen, uint8_t *content,
		uint32_t clen, uint8_t *msg, uint32_t *mlen);
int http_parse_response(uint8_t *msg, uint32_t mlen);
static int char_to_int(uint8_t *str, uint32_t slen);

int 
usage(const char *pname)
{
  emsg(">> Usage: %s -d <domain> -p <port> -s <gateway domain> -g <gateway port> -l <log file name>", pname);
  emsg(">> Example: %s -d www.alice.com -p 5555 -s www.gateway.com -g 5556 -l log", pname);
  exit(1);
}

int 
main(int argc, char *argv[])
{   
	int i, rc, num_of_threads;
  int c, sport, gport;
  const char *pname;
  const char *sdomain, *gdomain;
  const char *lname;
  SSL_CTX *ctx;
  info_t info;
  
  pname = argv[0];
  sdomain = DEFAULT_SERVER_DOMAIN_NAME;
  sport = DEFAULT_SERVER_PORT_NUMBER;
  gdomain = DEFAULT_GATEWAY_DOMAIN_NAME;
  gport = DEFAULT_GATEWAY_PORT_NUMBER;
  num_of_threads = DEFAULT_NUM_THREADS;
  lname = NULL;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"domain", required_argument, 0, 'd'},
      {"port", required_argument, 0, 'p'}, 
      {"gateway-domain", required_argument, 0, 's'},
      {"gateway-port", required_argument, 0, 'g'},
      {"log", required_argument, 0, 'l'},
      {"threads", required_argument, 0, 't'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "d:p:l:s:g:t:0", long_options, &option_index);

    if (c == -1)
      break;

    switch (c)
    {
      case 'l':
        lname = optarg;
        break;
      case 'd':
        sdomain = optarg;
        break;
      case 'p':
        sport = atoi(optarg);
        break;
      case 's':
        gdomain = optarg;
        break;
      case 'g':
        gport = atoi(optarg);
        break;
      case 't':
        num_of_threads = atoi(optarg);
        break;
      default:
        usage(pname);
    }
  }

  imsg("Log File Name: %s", lname);
  imsg("Server Domain: %s", sdomain);
  imsg("Server Port: %d", sport);
  imsg("Gateway Domain: %s", gdomain);
  imsg("Gateway Port: %d", gport);
  imsg("Number of Threads: %d", num_of_threads);

  SSL_library_init();
  OpenSSL_add_all_algorithms();

	pthread_t thread[num_of_threads];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

	ctx = init_client_ctx();
	load_ecdh_params(ctx);

  info.ctx = ctx;
  info.sdomain = sdomain;
  info.sport = sport;
  info.gdomain = gdomain;
  info.gport = gport;

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
  const char *sdomain, *gdomain;
	int i, sport, gport, server, gateway, ret;
  struct sockaddr_in ssin, gsin;
  socklen_t ssz, gsz;
  unsigned char buf[BUF_SIZE];
	SSL *ssl;
	SSL_SESSION *session = NULL;
  BIO *b;
	int len;
  info_t *info;
  info = (info_t *)data;
  sdomain = info->sdomain;
  sport = info->sport;
  gdomain = info->gdomain;
  gport = info->gport;
  
  b = BIO_new(BIO_s_mem());
  ssl = SSL_new(info->ctx);   
  dmsg("before open connection to gateway");
	gateway = open_connection(gdomain, gport, &gsin, &gsz);
  dmsg("gsin: %p, gsz: %u", &gsin, gsz);
  if (sendto(gateway, "Delegation", 10, 0, (struct sockaddr *) &gsin, gsz) < 0)
  {
    emsg("sendto error");
    abort();
  }
  dmsg("send the start message complete");

  len = recvfrom(gateway, &buf, BUF_SIZE, 0, (struct sockaddr *) &gsin, &gsz);
  imsg("Recevied SSL Session Length: %d", len);

  server = open_connection(sdomain, sport, &ssin, &ssz);
	SSL_set_fd(ssl, server);
	SSL_set_tlsext_host_name(ssl, sdomain);

  BIO_write(b, buf, len);
  session = PEM_read_bio_SSL_SESSION(b, NULL, NULL, NULL);

	if (session != NULL)
  {
    imsg("Succeed to read the SSL session");
		SSL_set_session(ssl, session);
  }
  else
  {
    emsg("Failed to read the SSL session");
    abort();
  }

	dmsg("Set server name: %s", sdomain);

	imsg("PROGRESS: DTLS Handshake Start");

	if ((ret = SSL_connect(ssl)) < 0) {
		emsg("ret after SSL_connect: %d", ret);
		ERR_print_errors_fp(stderr);
		goto err;
	} else {
    if (SSL_session_reused(ssl))
    {
      imsg("Succeed to resume the SSL session: Connected with %s", SSL_get_cipher(ssl));
    }
    else
    {
      emsg("Failed to resume the SSL session: Connected with %s", SSL_get_cipher(ssl));
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

int open_connection(const char *domain, int port, struct sockaddr_in *addr, socklen_t *sz)
{
  fstart("domain: %s, port: %d, addr: %p, sz: %p", domain, port, addr, sz);
  int sd;
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
  *sz = sizeof(*addr);

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

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#ifndef _WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif
#include <sys/stat.h>
#include <getopt.h>

#include <event.h>
#include <debug.h>
#include <defines.h>
#include <logger.h>
#include "server.h"

static int init = 0;
static void udp_cb(const int fd, short int event, void *arg);
static clock_t start = 0;
static clock_t end = 0;
int open_listener(int port);

int 
usage(const char *pname)
{
  emsg(">> Usage: %s -p <port> -c <certificate file> -k <private key file> -l <log file>", pname);
  emsg(">> Example: %s -p 5555 ../certs/cert.pem -k ../certs/priv.key -l log", pname);
  exit(1);
}

int
main(int argc, char **argv)
{
	struct event_base *base;
  
  SSL_CTX *ctx;
  info_t *info;
  
  int c, port, fd;
  const char *pname;
  const char *log_prefix;
  const char *cert;
  const char *key;
  struct event udp_event;

  pname = argv[0];
  port = DEFAULT_PORT_NUMBER;
  log_prefix = NULL;
  cert = DEFAULT_CERT_PATH;
  key = DEFAULT_KEY_PATH;

  /* Get the command line arguments */
  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"log", required_argument, 0, 'l'},
      {"port", required_argument, 0, 'p'},
      {"cert", required_argument, 0, 'c'},
      {"key", required_argument, 0, 'k'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "l:p:c:k:0", long_options, &option_index);

    if (c == -1)
      break;
    
    switch (c)
    {
      case 'l':
        log_prefix = optarg;
        break;
      case 'p':
        port = atoi(optarg);
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

  imsg("Log Prefix: %s", log_prefix);
  imsg("Port: %d", port);
  imsg("Certificate: %s", cert);
  imsg("Private Key: %s", key);

  initialization();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  ctx = init_server_ctx(cert, key);
  info = (info_t *) malloc(sizeof(info_t));
  memset(info, 0x0, sizeof(info_t));
  info->ctx = ctx;
  info->log_prefix = log_prefix;

  fd = open_listener(port);
  base = event_init();
  event_set(&udp_event, fd, EV_READ|EV_PERSIST, udp_cb, info);
  event_add(&udp_event, 0);

  event_dispatch();

  finalization();

	imsg("done");
	return 0;
}

static void
udp_cb(const int fd, short int event, void *user_data)
{
  fstart("fd: %d, event: %d, user_data: %p", fd, event, user_data);
  client_t *client;
  SSL *ssl;
  BIO *rbio, *wbio;
  struct sockaddr_in sin;
  socklen_t sz;
  unsigned char rbuf[BUF_SIZE];
  unsigned char wbuf[BUF_SIZE];
  int rlen, wlen;
	info_t *info = (info_t *)user_data;
  client = info->client;
  imsg("info->client: %p", info->client);
  
  if (!client)
  {
    start = clock();
    imsg("Initialize the client context");
    client = init_client_ctx();

    struct stat st = {0};
    if (stat(DEFAULT_LOG_DIRECTORY, &st) < 0)
    {
      mkdir(DEFAULT_LOG_DIRECTORY, 0755);
    }

    dmsg("info->log_prefix: %s", info->log_prefix);
    if (info->log_prefix)
    {
      snprintf(client->log_file, MAX_FILE_NAME_LEN, "%s/%s_%d", DEFAULT_LOG_DIRECTORY, 
          info->log_prefix, fd);
      dmsg("Client's log file prefix: %s", client->log_file);
    }

    ssl = SSL_new(info->ctx);
    if (!ssl)
    {
      emsg("SSL initialization error");
      abort();
    }
    imsg("SSL initialization success: client->ssl: %p", ssl);

    rbio = BIO_new(BIO_s_mem());
    if (!rbio)
    {
      emsg("BIO initialization error");
      abort();
    }
    imsg("BIO initialization success");

    wbio = BIO_new(BIO_s_mem());
    if (!wbio)
    {
      emsg("BIO initialization error");
      abort();
    }
    imsg("BIO initialization success");

    SSL_set_bio(ssl, rbio, wbio);
    SSL_set_accept_state(ssl);
    client->ssl = ssl;
    info->client = client;
    imsg("Initialize the client context success");
  }
  
  rlen = wlen = -1;
  ssl = client->ssl;
  rlen = recvfrom(fd, &rbuf, BUF_SIZE, 0, (struct sockaddr *) &sin, &sz);
  if (rlen == -1)
  {
    emsg("recvfrom error");
    event_loopbreak();
  }
  imsg("rlen: %d", rlen);

  if (rlen > 0)
  {
    imsg("no error during reading");

    if (SSL_is_init_finished(ssl))
    {
      end = clock();
      imsg("DTLS session is established: %lf ms", ((double) (end - start) * 1000)/CLOCKS_PER_SEC);
    }
    else
    {
      BIO_write(SSL_get_rbio(ssl), rbuf, rlen);
      SSL_do_handshake(ssl);
      wlen = BIO_read(SSL_get_wbio(ssl), wbuf, BUF_SIZE);
      dmsg("length to write: %ld", wlen);
      if (wlen > 0)
      {
        if (sendto(fd, wbuf, wlen, 0, (struct sockaddr *) &sin, sz) == -1)
        {
          emsg("sendto error");
          event_loopbreak();
        }
      }
    }
  }
  ffinish();
}

int open_listener(int port)
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

SSL_CTX *
init_server_ctx(const char *cert, const char *key)
{
  fstart("cert: %p, key: %p", cert, key);
  SSL_CTX *ret;
  SSL_METHOD *method;
  EC_KEY *ecdh;

  method = (SSL_METHOD *) DTLS_server_method();
  ret = SSL_CTX_new(method);

  SSL_CTX_set_cipher_list(ret, "ECDHE-ECDSA-AES128-GCM-SHA256");

  if (SSL_CTX_use_certificate_file(ret, cert, SSL_FILETYPE_PEM) <= 0)
  {
    emsg("SSL_CTX_use_certificate_file error");
    abort();
  }
  imsg("SSL_CTX_use_certificate_file success");

  if (SSL_CTX_use_PrivateKey_file(ret, key, SSL_FILETYPE_PEM) <= 0)
  {
    emsg("SSL_CTX_use_PrivateKey_file error");
    abort();
  }
  imsg("SSL_CTX_use_PrivateKey_file success");

  if (!SSL_CTX_check_private_key(ret))
  {
    emsg("SSL_CTX_check_private_key error");
    abort();
  }
  imsg("SSL_CTX_check_private_key success");

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(!ecdh)
  {
    emsg("Set ECDH error");
    abort();
  }
  imsg("Set ECDH success");

  if (SSL_CTX_set_tmp_ecdh(ret, ecdh) != 1)
  {
    emsg("SSL_CTX_set_tmp_ecdh error");
    abort();
  }

  SSL_CTX_set_session_cache_mode(ret, SSL_SESS_CACHE_BOTH);

  ffinish();
  return ret;
}

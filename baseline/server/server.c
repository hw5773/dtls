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

#include <event2/listener.h>
#include <debug.h>
#include <defines.h>
#include <logger.h>
#include "server.h"

static const char message[] = "Hello, World!\n";

static void listener_cb(struct evconnlistener *, evutil_socket_t,
    struct sockaddr *, int socklen, void *);
static void conn_readcb(struct bufferevent *, void *);
static void conn_eventcb(struct bufferevent *, short, void *);
static void signal_cb(evutil_socket_t, short, void *);

int usage(const char *pname)
{
  emsg(">> Usage: %s -p <port> -c <certificate file> -k <private key file> -l <log file>", pname);
  emsg(">> Example: %s -p 5555 ../certs/cert.pem -k ../certs/priv.key -l log", pname);
  exit(1);
}

int
main(int argc, char **argv)
{
	struct event_base *base;
	struct evconnlistener *listener;
	struct event *signal_event;
  
	struct sockaddr_in sin;

  SSL_CTX *ctx;
  info_t *info;
  
  int c, port;
  const char *pname;
  const char *log_prefix;
  const char *cert;
  const char *key;

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
  ctx = init_server_ctx(cert, key);
  info = (info_t *) malloc(sizeof(info_t));
  memset(info, 0x0, sizeof(info));
  info->ctx = ctx;
  info->log_prefix = log_prefix;

	base = event_base_new();
	if (!base) {
		emsg("Could not initialize libevent!");
		return 1;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);

	listener = evconnlistener_new_bind(base, listener_cb, (void *)info,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_THREADSAFE, 
      -1, (struct sockaddr*)&sin, sizeof(sin));

	if (!listener) {
		emsg("Could not create a listener!");
		return 1;
	}

	signal_event = evsignal_new(base, SIGINT, signal_cb, (void *)base);

	if (!signal_event || event_add(signal_event, NULL)<0) {
		emsg("Could not create/add a signal event!");
		return 1;
	}

	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_free(signal_event);
	event_base_free(base);

  finalization();

	imsg("done");
	return 0;
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
  fstart();
  client_t *client;
  int idx;
  SSL *ssl;
  BIO *rbio, *wbio;
	struct bufferevent *bev;
  struct event_base *base;
	info_t *info = (info_t *)user_data;

  if (evutil_make_socket_nonblocking(fd) < 0)
  {
    emsg("Failed to set the socket to non-blocking");
    abort();
  }
  imsg("Set the socket to non-blocking");

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

  base = get_event_base(&idx);
  if (!base)
  {
    emsg("No event base is assigned");
    return;
  }
  client->idx = idx;

	bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		fprintf(stderr, "Error constructing bufferevent!");
		return;
	}
	bufferevent_setcb(bev, conn_readcb, NULL, conn_eventcb, client);
	bufferevent_enable(bev, EV_READ);
  event_base_dispatch(base);

  ffinish();
}

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
  fstart();
  client_t *client;
  SSL *ssl;
  size_t rlen, wlen;
  uint8_t rbuf[BUF_SIZE] = {0, };
  uint8_t wbuf[BUF_SIZE] = {0, };

  client = (client_t *)user_data;
  ssl = client->ssl;

  rlen = bufferevent_read(bev, rbuf, BUF_SIZE);
  if (rlen > 0)
  {
    imsg("no error during reading");
    if (SSL_is_init_finished(client->ssl))
    {
      dmsg("client->log_file: %s", client->log_file);
      dmsg("after the TLS session is established");
    }
    else
    {
      dmsg("before the TLS session is established");
      dmsg("receive the TLS message from a client: %ld bytes", rlen);
      BIO_write(SSL_get_rbio(ssl), rbuf, rlen);
      dmsg("SSL_do_handshake: client->ssl: %p", ssl);
      SSL_do_handshake(ssl);
      wlen = BIO_read(SSL_get_wbio(ssl), wbuf, BUF_SIZE);
      dmsg("length to write: %ld", wlen);
      if (wlen > 0)
        bufferevent_write(bev, wbuf, wlen);
    }
  }
  ffinish();
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
  fstart();
  int idx;
  client_t *client;
	if (events & BEV_EVENT_EOF) {
		imsg("Connection closed.");
	} else if (events & BEV_EVENT_ERROR) {
		imsg("Got an error on the connection: %s",
		    strerror(errno));/*XXX win32*/
	}
	/* None of the other events can happen here, since we haven't enabled
	 * timeouts */
  
  client = (client_t *)user_data;
  idx = client->idx;

	bufferevent_free(bev);
  free_client_ctx(client);

  ffinish();
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
  fstart("sig: %p, events: %d, user_data: %p", sig, events, user_data);
  int i;
	struct event_base *base = user_data;
	struct timeval delay = {1, 0};

	imsg("Caught an interrupt signal; exiting cleanly in one second.");

	event_base_loopexit(base, &delay);

  for (i=0; i<MAX_THREADS; i++)
  {
    event_base_free(g_ebase[i]);
    g_ebase[i] = NULL;
    occupied[i] = 0;
  }
  ffinish();
}

SSL_CTX *init_server_ctx(const char *cert, const char *key)
{
  fstart("cert: %p, key: %p", cert, key);
  SSL_CTX *ret;
  SSL_METHOD *method;
  EC_KEY *ecdh;

  method = (SSL_METHOD *) DTLSv1_2_server_method();
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

  ffinish();
  return ret;
}

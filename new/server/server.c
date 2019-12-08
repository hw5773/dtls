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
  emsg(">> Usage: %s -p <port> -l <log file>", pname);
  emsg(">> Example: %s -p 5555 -l log", pname);
  exit(1);
}

int
main(int argc, char **argv)
{
	struct event_base *base;
  
  info_t *info;
  
  int c, port, client;
  const char *pname;
  const char *log_prefix;
  struct event udp_event;

  pname = argv[0];
  port = DEFAULT_PORT_NUMBER;
  log_prefix = NULL;

  /* Get the command line arguments */
  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"log", required_argument, 0, 'l'},
      {"port", required_argument, 0, 'p'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "l:p:0", long_options, &option_index);

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
      default:
        usage(pname);
    }
  }

  imsg("Log Prefix: %s", log_prefix);
  imsg("Port: %d", port);

  info = (info_t *) malloc(sizeof(info_t));
  memset(info, 0x0, sizeof(info_t));
  info->log_prefix = log_prefix;

  client = open_listener(port);

  start = clock();
  if ((ret = hip_dex(client, ROLE_RESPONDER)) < 0)
  {
    emsg("ret after HIP-DEX: %d", ret);
    goto err;
  }
  imsg("After HIP-DEX");

  if ((ret = tgk_agreement(client)) < 0)
  {
    emsg("Error in TGK Agreement");
    goto err;
  }

  if ((ret = tek_generation(client)) < 0)
  {
    emsg("Error in TEK Generation");
    goto err;
  }
  imsg("TEK Generation Success");
  end = clock();
  imsg("Connected with the client: %lf ms", ((double) (end - start) * 1000)/CLOCKS_PER_SEC);

err:
  if (end == 0)
    emsg("Error happened during handshake");

  if (server != -1)
    close(server);

	return 0;
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

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
#include "../common/hip_dex.h"

typedef struct info_st
{
  const char *domain;
  int port;
} info_t;

static clock_t start = 0;
static clock_t end = 0;

void *run(void *data);
int open_connection(const char *domain, int port);

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
  info_t info;
  
  pname = argv[0];
  domain = DEFAULT_DOMAIN_NAME;
  port = DEFAULT_PORT_NUMBER;
  num_of_threads = DEFAULT_NUM_THREADS;
  lname = NULL;

  while (1)
  {
    int option_index = 0;
    static struct option long_options[] = {
      {"domain", required_argument, 0, 'd'},
      {"port", required_argument, 0, 'p'}, 
      {"log", required_argument, 0, 'l'},
      {"threads", required_argument, 0, 't'},
      {0, 0, 0, 0}
    };

    c = getopt_long(argc, argv, "d:p:l:t:0", long_options, &option_index);

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
      default:
        usage(pname);
    }
  }

  imsg("Log File Name: %s", lname);
  imsg("Domain: %s", domain);
  imsg("Port: %d", port);
  imsg("Number of Threads: %d", num_of_threads);

  info.domain = domain;
  info.port = port;

	pthread_t thread[num_of_threads];
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	void *status;

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

	return 0;
}

void *run(void *data)
{	
  fstart("data: %p", data);
  const char *domain;
	int i, port, server, rlen, wlen, ret;
  unsigned char buf[BUF_SIZE];
  info_t *info;
  
  info = (info_t *)data;
  domain = info->domain;
  port = info->port;
  
	server = open_connection(domain, port);

  start = clock();
	if ((ret = hip_dex(server, ROLE_INITIATOR`)) < 0) 
  {
		emsg("ret after hip_dex: %d", ret);
		goto err;
	} 
  imsg("After HIP-DEX");

  if ((ret = tgk_agreement(server)) < 0)
  {
    emsg("Error in TGK Agreement");
    goto err;
  }
  imsg("TGK Generation Success");

  if ((ret = tek_generation(server)) < 0)
  {
    emsg("Error in TEK Generation");
    goto err;
  }
  imsg("TEK Generation Success");
  end = clock();
  imsg("Connected with the server: %lf ms", ((double) (end - start) * 1000)/CLOCKS_PER_SEC);

err: 
  if (end == 0)
    emsg("Error happened during handshake");

	if (server != -1)
		close(server);

  ffinish();
	return NULL;
}

int open_connection(const char *domain, int port)
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

  ffinish("sd: %d", sd);
  return sd;
}

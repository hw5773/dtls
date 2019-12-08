#ifndef __EDGE_H__
#define __EDGE_H__

#include <openssl/ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/event.h>

#include <defines.h>
#include "setting.h"

typedef struct client
{
  unsigned char log_file[MAX_FILE_NAME_LEN];
} client_t;

typedef struct info
{
  unsigned char dm_hit[HIT_LENGTH];
  const char *log_prefix;
  client_t *client;
} info_t;

struct event_base *g_ebase[MAX_THREADS];
int occupied[MAX_THREADS];
static int cnt = 0;

int initialization(void);
void finalization(void);
struct event_base *get_event_base(int *idx);

SSL_CTX *init_server_ctx(const char *cert, const char *key);
client_t *init_client_ctx(void);
void free_client_ctx(client_t *ctx);

#endif /* __EDGE_H__ */

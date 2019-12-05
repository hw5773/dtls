#include "server.h"
#include <debug.h>
#include <string.h>

int initialization(void)
{
  fstart();
  int i;
  for (i=0; i<MAX_THREADS; i++)
  {
    g_ebase[i] = event_base_new();
    occupied[i] = 0;
  }
  ffinish();
}

void finalization(void)
{
  fstart();
  int i;
  for (i=0; i<MAX_THREADS; i++)
  {
    if (g_ebase[i])
      event_base_free(g_ebase[i]);
    occupied[i] = 0;
    g_ebase[i] = NULL;
  }
  ffinish();
}

struct event_base *get_event_base(int *idx)
{
  fstart("idx: %p", idx);
  int i;
  struct event_base *ret;
  for (i=0; i<MAX_THREADS; i++)
  {
    if (occupied[i] == 0)
      break;
  }
  *idx = i;

  if (i < MAX_THREADS)
    ret = g_ebase[i];
  else
    ret = NULL;

  ffinish("ret: %p", ret);
  return ret;
}

client_t *init_client_ctx(void)
{
  fstart();
  client_t *ret;
  ret = (client_t *)malloc(sizeof(client_t));
  memset(ret, 0x0, sizeof(client_t));
  memset(ret->log_file, 0x0, MAX_FILE_NAME_LEN);

  ffinish("ret; %p", ret);
  return ret;
}

void free_client_ctx(client_t *ctx)
{
  fstart("ctx: %p", ctx);
  int idx;
  if (ctx)
  {
    if (ctx->ssl)
    {
      SSL_free(ctx->ssl);
      ctx->ssl = NULL;
    }

    idx = ctx->idx;
    if (g_ebase[idx] && occupied[idx])
    {
      event_base_free(g_ebase[idx]);
      occupied[idx] = 0;
      g_ebase[idx] = event_base_new();
    }
    free(ctx);
    ctx = NULL;
  }
  ffinish();
}

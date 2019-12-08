#include "prince.h"
#include <string.h>
#include <debug.h>
#include <sys/time.h>
#include <time.h>

int main(int argc, char *argv[])
{
  const char *test = "ABCDEFGH";
  const char *key = "ABCDEFGHIJKLMNOP";
  unsigned char tmp1[64], tmp2[64];
  int tlen1, tlen2;

  clock_t start, end;
  init_prince();

  start = clock();
  prince_encrypt(key, strlen(key), test, strlen(test), tmp1, &tlen1);
  end = clock();
  imsg("elapsed time: %lf ms", ((double) (end - start) * 1000 / CLOCKS_PER_SEC));
  dprint("Encrypt", tmp1, 0, tlen1, 8);

  prince_decrypt(key, strlen(key), tmp1, tlen1, tmp2, &tlen2);
  dprint("Decrypt", tmp2, 0, tlen2, 8);
  imsg("Result: %s", tmp2);
  imsg("encryption elapsed time: %lf ms", ((double) (end - start) * 1000 / CLOCKS_PER_SEC));

  return 0;
}

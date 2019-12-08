#include "prince.h"
#include <string.h>
#include <debug.h>

int main(int argc, char *argv[])
{
  const char *test = "ABCDEFGH";
  const char *key = "ABCDEFGHIJKLMNOP";
  unsigned char tmp1[64], tmp2[64];
  int tlen1, tlen2;

  initialization();
  prince_encrypt(key, strlen(key), test, strlen(test), tmp1, &tlen1);
  dprint("Encrypt", tmp1, 0, tlen1, 8);

  prince_decrypt(key, strlen(key), tmp1, tlen1, tmp2, &tlen2);
  dprint("Decrypt", tmp2, 0, tlen2, 8);
  imsg("Result: %s", tmp2);

  return 0;
}

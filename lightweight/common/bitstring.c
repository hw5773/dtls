#include "bitstring.h"
#include <stdlib.h>
#include <debug.h>

unsigned char *byte2bitstring(unsigned char *byte, int bytelen, int *bitlen)
{
  fstart("byte: %p, bytelen: %d, bitlen: %p", byte, bytelen, bitlen);
  assert(byte != NULL);
  assert(bytelen > 0);
  assert(bitlen != NULL);

  unsigned char *ret;
  unsigned char tmp;
  int i, j;
  *bitlen = bytelen * 8;
  ret = (unsigned char *)malloc(*bitlen);

  for (i=0; i<bytelen; i++)
  {
    tmp = byte[i];
    for (j=7; j>=0; j--)
    {
      ret[8*i + j] = tmp % 2;
      tmp = tmp / 2;
    }
  }

  ffinish();
  return ret;
}

unsigned char *bitstring2byte(unsigned char *bitstring, int bitlen, int *bytelen)
{
  fstart("bitstring: %p, bitlen: %d, bytelen: %p", bitstring, bitlen, bytelen);
  assert(bitstring != NULL);
  assert(bitlen % 8 == 0);
  assert(bytelen != NULL);

  unsigned char *ret;
  unsigned char tmp;
  int i, j;
  *bytelen = bitlen / 8;
  ret = (unsigned char *)malloc(*bytelen);

  for (i=0; i<*bytelen; i++)
  {
    tmp = 0;
    for (j=8*i; j<=8*i + 7; j++)
    {
      printf("%d ", bitstring[j]);
      tmp = (tmp << 1) + bitstring[j];
      printf("(%d) ", tmp);
    }
    printf("\n");
    ret[i] = tmp;
  }

  ffinish();
  return ret;
}

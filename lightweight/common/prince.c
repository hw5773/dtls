#include "prince.h"
#include <stdlib.h>
#include <string.h>
#include <debug.h>

void init_prince()
{
  fstart();
  int i, bitlen;

  for (i=0; i<12; i++)
  {
    bitrc[i] = byte2bitstring(RC[i], 16, &bitlen);
  }

  ffinish();
}

unsigned char *sbox(unsigned char *data, int dlen, int *rlen, unsigned char *box)
{
  fstart("data: %p, dlen: %d, rlen: %p, box: %p", data, dlen, rlen, box);
  assert(data != NULL);
  assert(dlen >= 16);
  assert(rlen != NULL);
  assert(box != NULL);

  unsigned char *ret;
  int i, j, tmp1, tmp2;
  ret = (unsigned char *)malloc(64);
  for (i=0; i<dlen; i+=4)
  {
    tmp1 = 0;
    for (j=i; j<i+4; j++)
    {
      tmp1 = tmp1 << 2 | data[j];
    }
    tmp2 = box[tmp1];
    ret[i+3] = tmp2 % 2;
    tmp2 = tmp2 / 2;
    ret[i+2] = tmp2 % 2;
    tmp2 = tmp2 / 2;
    ret[i+1] = tmp2 % 2;
    tmp2 = tmp2 / 2;
    ret[i] = tmp2 % 2;
  }

  *rlen = 64;
  return ret;
}

unsigned char *m0(unsigned char *data, int dlen, int *rlen)
{
  fstart("data: %p, dlen: %d, rlen: %p", data, dlen, rlen);
  assert(data != NULL);
  assert(dlen >= 16);
  assert(rlen != NULL);

  unsigned char *ret;
  ret = (unsigned char *)malloc(16);

  ret[0] = data[4] ^ data[8] ^ data[12];
  ret[1] = data[1] ^ data[9] ^ data[13];
  ret[2] = data[2] ^ data[6] ^ data[14];
  ret[3] = data[3] ^ data[7] ^ data[11];

  ret[4] = data[0] ^ data[4] ^ data[8];
  ret[5] = data[5] ^ data[9] ^ data[13];
  ret[6] = data[2] ^ data[10] ^ data[14];
  ret[7] = data[3] ^ data[7] ^ data[15];

  ret[8] = data[0] ^ data[4] ^ data[12];
  ret[9] = data[1] ^ data[5] ^ data[9];
  ret[10] = data[6] ^ data[10] ^ data[14];
  ret[11] = data[3] ^ data[11] ^ data[15];

  ret[12] = data[0] ^ data[8] ^ data[12];
  ret[13] = data[1] ^ data[5] ^ data[13];
  ret[14] = data[2] ^ data[6] ^ data[10];
  ret[15] = data[7] ^ data[11] ^ data[15];

  *rlen = 16;

  ffinish();
  return ret;
}

unsigned char *m1(unsigned char *data, int dlen, int *rlen)
{
  fstart("data: %p, dlen: %d, rlen: %p", data, dlen, rlen);
  assert(data != NULL);
  assert(dlen >= 16);
  assert(rlen != NULL);

  unsigned char *ret;
  ret = (unsigned char *)malloc(16);
 
  ret[0] = data[0] ^ data[4] ^ data[8];
  ret[1] = data[5] ^ data[9] ^ data[13];
  ret[2] = data[2] ^ data[10] ^ data[14];
  ret[3] = data[3] ^ data[7] ^ data[15];

  ret[4] = data[0] ^ data[4] ^ data[12];
  ret[5] = data[1] ^ data[5] ^ data[9];
  ret[6] = data[6] ^ data[10] ^ data[14];
  ret[7] = data[3] ^ data[11] ^ data[15];

  ret[8] = data[0] ^ data[8] ^ data[12];
  ret[9] = data[1] ^ data[5] ^ data[13];
  ret[10] = data[2] ^ data[6] ^ data[10];
  ret[11] = data[7] ^ data[11] ^ data[15];

  ret[12] = data[4] ^ data[8] ^ data[12];
  ret[13] = data[1] ^ data[9] ^ data[13];
  ret[14] = data[2] ^ data[6] ^ data[14];
  ret[15] = data[3] ^ data[7] ^ data[11];

  *rlen = 16;
  
  ffinish();
  return ret;
}

unsigned char *shiftrows(unsigned char *data, int dlen, int *rlen, int inverse)
{
  fstart("data: %p, dlen: %d, rlen: %p, inverse: %d", data, dlen, rlen, inverse);
  assert(data != NULL);
  assert(dlen >= 16);
  assert(rlen != NULL);

  unsigned char *p, *ret, *tmp1, *tmp2, *tmp3, *tmp4;
  int i, idx;
  ret = (unsigned char *)malloc(64);
  memset(ret, 0x0, 64);
  idx = 0;

  for (i=0; i<dlen; i+=4)
  {
    ret[idx * 4] = data[i];
    ret[idx * 4 + 1] = data[i + 1];
    ret[idx * 4 + 2] = data[i + 2];
    ret[idx * 4 + 3] = data[i + 3];

    if (inverse == FALSE)
    {
      idx = (idx + 13) % 16;
    }
    else
    {
      idx = (idx + 5) % 16;
    }
  }

  *rlen = 64;
  ffinish();
  return ret;
}

unsigned char *mprime(unsigned char *data, int dlen, int *rlen)
{
  fstart("data: %p, dlen: %d, rlen: %p", data, dlen, rlen);
  assert(data != NULL);
  assert(dlen >= 64);
  assert(rlen != NULL);

  unsigned char *p, *ret, *tmp1, *tmp2, *tmp3, *tmp4;
  int len;
  ret = (unsigned char *)malloc(64);

  p = data;
  tmp1 = m0(p, 16, &len);
  p += 16;
  tmp2 = m1(p, 16, &len);
  p += 16;
  tmp3 = m1(p, 16, &len);
  p += 16;
  tmp4 = m0(p, 16, &len);

  p = ret;
  memcpy(p, tmp1, 16);
  p += 16;
  memcpy(p, tmp2, 16);
  p += 16;
  memcpy(p, tmp3, 16);
  p += 16;
  memcpy(p, tmp4, 16);

  free(tmp1);
  free(tmp2);
  free(tmp3);
  free(tmp4);

  *rlen = 64;
  ffinish();
  return ret;
}

unsigned char *firstrounds(unsigned char *data, int dlen, unsigned char *key, int klen, 
    int *rlen)
{
  fstart("data: %p, dlen: %d, key: %p, klen: %d, rlen: %p", data, dlen, key, klen, rlen);
  assert(data != NULL);
  assert(dlen > 0);
  assert(key != NULL);
  assert(klen > 0);

  int i, j, len;
  unsigned char tmp[64];

  for (i=1; i<=5; i++)
  {
    data = sbox(data, dlen, &len, S);
    data = mprime(data, dlen, &len);
    data = shiftrows(data, dlen, &len, FALSE);
    for (j=0; j<64; j++)
      tmp[j] = bitrc[i][j] ^ key[j];

    for (j=0; j<64; j++)
      data[j] = data[j] ^ tmp[j];
  }

  *rlen = dlen;
  ffinish();
  return data;
}

unsigned char *lastrounds(unsigned char *data, int dlen, unsigned char *key, int klen,
    int *rlen)
{
  fstart("data: %p, dlen: %d, key: %p, klen: %d, rlen: %p", data, dlen, key, klen, rlen);
  assert(data != NULL);
  assert(dlen > 0);
  assert(key != NULL);
  assert(klen > 0);

  int i, j, len;
  unsigned char tmp[64];

  for (i=6; i<=10; i++)
  {
    for (j=0; j<64; j++)
      tmp[j] = bitrc[i][j] ^ key[j];

    for (j=0; j<64; j++)
      data[j] = data[j] ^ tmp[j];

    data = shiftrows(data, dlen, &len, TRUE);
    data = mprime(data, dlen, &len);
    data = sbox(data, dlen, &len, Sinv);
  }

  *rlen = dlen;
  ffinish();
  return data;
}

unsigned char *princecore(unsigned char *data, int dlen, unsigned char *key, int klen, 
    int *rlen)
{
  fstart("data: %p, dlen: %d, key: %p, klen: %d, rlen: %p", data, dlen, key, klen, rlen);
  assert(data != NULL);
  assert(dlen > 0);
  assert(key != NULL);
  assert(klen > 0);

  int i, len;
  unsigned char tmp[64];

  for (i=0; i<64; i++)
    tmp[i] = key[i] ^ bitrc[0][i];

  for (i=0; i<64; i++)
    data[i] = data[i] ^ tmp[i];
  data = firstrounds(data, dlen, key, klen, &len);

  data = sbox(data, dlen, &len, S);
  data = mprime(data, dlen, &len);
  data = sbox(data, dlen, &len, Sinv);

  data = lastrounds(data, dlen, key, klen, &len);

  for (i=0; i<64; i++)
    tmp[i] = key[i] ^ bitrc[11][i];

  for (i=0; i<64; i++)
    data[i] = data[i] ^ tmp[i];

  *rlen = dlen;
  ffinish();
  return data;
}

unsigned char *outer(unsigned char *data, int dlen, unsigned char *key, int klen, int *rlen,
    int decrypt)
{
  fstart("data: %p, dlen: %d, key: %p, klen: %d, rlen: %p, decrypt: %d", data, dlen, key, klen, rlen, decrypt);
  assert(data != NULL);
  assert(dlen > 0);
  assert(key != NULL);
  assert(klen > 0);
  assert(rlen != NULL);

  unsigned char *k0, *k0prime, *k0tmp, *tmp, *k1;
  int i, len;

  k0 = (unsigned char *)malloc(64);
  k0prime = (unsigned char *)malloc(64);
  k0tmp = (unsigned char *)malloc(64);
  k1 = (unsigned char *)malloc(64);

  memcpy(k0, key, 64);
  memcpy(k0prime + 1, k0, 63);
  k0prime[0] = k0[63];
  memset(k0tmp, 0x0, 64);
  k0tmp[63] = k0[0]; // k0tmp = k0 >> 63

  // k0prime ^= k0 >> 63
  for (i=0; i<64; i++)
  {
    k0prime[i] = k0prime[i] ^ k0tmp[i];
  }

  if (decrypt == TRUE)
  {
    tmp = k0;
    k0 = k0prime;
    k0prime = k0;
  }

  memcpy(k1, key + 64, 64);
  for (i=0; i<64; i++)
  {
    data[i] = k0[i] ^ data[i];
  }

  data = princecore(data, dlen, k1, 64, &len);

  for (i=0; i<64; i++)
  {
    data[i] = data[i] ^ k0prime[i];
  }

  *rlen = dlen;

  //free(k0);
  //free(k0prime);
  //free(k0tmp);
  //free(k1);

  return data;
}

int prince_encrypt(unsigned char *key, int klen, unsigned char *msg, int mlen,
    unsigned char *ciph, int *clen)
{
  fstart("key: %p, klen: %d, msg: %p, mlen: %d, ciph: %p, clen: %d", key, klen, msg, mlen, ciph, clen);

  int ret;

  unsigned char *cmsg; // converted message
  int cmlen; // converted message length
  unsigned char *ckey; // converted key
  int cklen; // converted key length

  unsigned char *bciph;
  int bclen;
  unsigned char *tmp;
  int tlen;

  ret = TRUE;

  cmsg = byte2bitstring(msg, mlen, &cmlen);
  ckey = byte2bitstring(key, klen, &cklen);

  bciph = outer(cmsg, cmlen, ckey, cklen, &bclen, FALSE);
  
  tmp = bitstring2byte(bciph, bclen, &tlen);
  memcpy(ciph, tmp, tlen);
  *clen = tlen;

  free(cmsg);
  free(ckey);
  free(tmp);
  ffinish();
  return ret;
}

int prince_decrypt(unsigned char *key, int klen, unsigned char *ciph, int clen,
    unsigned char *msg, int *mlen)
{
  fstart("key: %p, klen: %d, ciph: %p, clen: %d, msg: %p, mlen: %d", key, klen, ciph, clen, msg, mlen);

  int ret;

  unsigned char *cciph; // converted cipher
  int cclen; // converted ciphertext length
  unsigned char *ckey; //converted key
  int cklen; // converted key length

  unsigned char *bmsg;
  int bmlen;
  unsigned char *tmp;
  int tlen;

  ret = TRUE;

  cciph = byte2bitstring(ciph, clen, &cclen);
  ckey = byte2bitstring(key, klen, &cklen);

  bmsg = outer(cciph, cclen, ckey, cklen, &bmlen, TRUE);

  tmp = bitstring2byte(bmsg, bmlen, &tlen);
  memcpy(msg, tmp, tlen);
  *mlen = tlen;

  free(cciph);
  free(ckey);
  free(tmp);
  ffinish();
  return ret;
}

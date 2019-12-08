#ifndef __BITSTRING_H__
#define __BITSTRING_H__

unsigned char *byte2bitstring(unsigned char *byte, int bytelen, int *bitlen);
unsigned char *bitstring2byte(unsigned char *bitstring, int bitlen, int *bytelen);

#endif /* __BITSTRING_H__ */

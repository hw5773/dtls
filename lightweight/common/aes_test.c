#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <time.h>
#include <sys/time.h>
#define BUF_SIZE 1024

int main(int argc, char *argv[])
{
  clock_t start, end;
  unsigned char key[32] = "01234567890123456789012345678901";
  unsigned char iv[16] = "0123456789012345";
  const char *msg = "ABCDEFGH";
  unsigned char ciph[BUF_SIZE];
  unsigned char plain[BUF_SIZE];
  int len;
  EVP_CIPHER_CTX *ctx;
  ctx = EVP_CIPHER_CTX_new();

  start = clock();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciph, &len, msg, strlen(msg));
  EVP_EncryptFinal_ex(ctx, ciph + len, &len);
  end = clock();

  printf("Elapsed time encryption: %lf ms\n", ((double) (end - start) * 1000 / CLOCKS_PER_SEC));
  return 0;
}

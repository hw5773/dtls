#ifndef __SETTING_H__
#define __SETTING_H__

#include <openssl/sha.h>

#define FAIL -1

#define DEFAULT_PORT_NUMBER 5555
#define DEFAULT_CERT_PATH "../../certs/cert.pem"
#define DEFAULT_KEY_PATH "../../certs/priv.key"
#define DEFAULT_LOG_DIRECTORY "logs"

#define HIT_LENGTH SHA256_DIGEST_LENGTH

#endif /* __SETTING_H__ */

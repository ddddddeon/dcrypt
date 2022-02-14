#ifndef DCRYPT_H
#define DCRYPT_H

#include <openssl/evp.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifndef DCRYPT_MIN_RSA_BITS
#define DCRYPT_MIN_RSA_BITS 1024
#endif

#ifndef DCRYPT_MAX_RSA_BITS
#define DCRYPT_MAX_RSA_BITS 65535
#endif

#ifndef DCRYPT_VERBOSE
#define DCRYPT_VERBOSE 0
#else
#define DCRYPT_VERBOSE 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DCRYPT_PKEY_free(key) \
  do {                        \
    EVP_PKEY_free(key);       \
  } while (0)

typedef EVP_PKEY DCRYPT_PKEY;

DCRYPT_PKEY *GenerateKey(int bits);
bool KeyToFile(DCRYPT_PKEY *key, char *out_file, bool is_private);
unsigned char *KeyToString(DCRYPT_PKEY *privkey, bool is_private);
DCRYPT_PKEY *FileToKey(char *in_file, bool is_private);
DCRYPT_PKEY *StringToKey(unsigned char *key_string, bool is_private);
unsigned char *Sign(char *message, DCRYPT_PKEY *key);
bool Verify(char *message, unsigned char *signature, DCRYPT_PKEY *pubkey,
            int key_length);
unsigned char *GenerateRandomBytes(int size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif /* !DCRYPT_H */

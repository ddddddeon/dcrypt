#ifndef DCRYPT_H
#define DCRYPT_H

#include <openssl/evp.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
namespace dcrypt {
#endif

typedef EVP_PKEY DCRYPT_PKEY;

DCRYPT_PKEY *GenerateKey(int bits);
bool KeyToFile(DCRYPT_PKEY *key, char *out_file, bool is_private);
unsigned char *KeyToString(DCRYPT_PKEY *privkey, bool is_private);
DCRYPT_PKEY *FileToKey(char *in_file, bool is_private);
DCRYPT_PKEY *StringToKey(unsigned char *key_string, bool is_private);
unsigned char *Sign(char *message, DCRYPT_PKEY *key);
bool Verify(char *message, unsigned char *signature, DCRYPT_PKEY *pubkey);
unsigned char *GenerateRandomBytes(int size);

#ifdef __cplusplus
}  // namespace dcrypt
#endif

#endif /* !DCRYPT_H */

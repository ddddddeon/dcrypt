#ifndef DCRYPT_H
#define DCRYPT_H

#include <openssl/evp.h>

#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
namespace dcrypt {
#endif

EVP_PKEY *GenerateKey();
bool KeyToFile(EVP_PKEY *key, char *out_file, bool is_private);
unsigned char *KeyToString(EVP_PKEY *privkey, bool is_private);
EVP_PKEY *FileToKey(char *in_file, bool is_private);
EVP_PKEY *StringToKey(unsigned char *key_string, bool is_private);
unsigned char *Sign(char *message, EVP_PKEY *key);
bool Verify(char *message, unsigned char *signature, EVP_PKEY *pubkey);
unsigned char *GenerateRandomBytes(int size);

#ifdef __cplusplus
}  // namespace dcrypt
#endif

#endif /* !DCRYPT_H */

#include "dcrypt.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <string.h>

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

#define HANDLE_ERROR(message, handle)                      \
  do {                                                     \
    if (DCRYPT_VERBOSE == 1) {                             \
      printf("%s (%s:%d)\n", message, __FILE__, __LINE__); \
    }                                                      \
    handle;                                                \
  } while (0)

#define CHECK_NOT_EQUAL(val, ret, message, handle) \
  do {                                             \
    if (ret != val) {                              \
      HANDLE_ERROR(message, handle);               \
    }                                              \
  } while (0)

#define CHECK_EQUAL(val, ret, message, handle) \
  do {                                         \
    if (ret == val) {                          \
      HANDLE_ERROR(message, handle);           \
    }                                          \
  } while (0)

#define CHECK_MD(ret, handle) \
  CHECK_NOT_EQUAL(1, ret, "Message Digest failed", EVP_MD_CTX_free(ctx); handle)

#ifdef __cplusplus
namespace dcrypt {
#endif

DCRYPT_PKEY *GenerateKey(int bits) {
  if (bits < DCRYPT_MIN_RSA_BITS || bits > DCRYPT_MAX_RSA_BITS) {
    if (DCRYPT_VERBOSE == 1) {
      printf(
          "RSA key length must be longer than %d bits and shorter than %d "
          "bits\n",
          DCRYPT_MIN_RSA_BITS, DCRYPT_MAX_RSA_BITS);
    }
    return NULL;
  }

  EVP_PKEY_CTX *ctx = NULL;
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  CHECK_EQUAL(NULL, ctx, "Could not create EVP_PKEY context", return NULL);

  int ret = EVP_PKEY_keygen_init(ctx);
  CHECK_NOT_EQUAL(1, ret, "Could not initialize EVP_PKEY context", return NULL);

  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
  EVP_PKEY *key = NULL;
  EVP_PKEY_keygen(ctx, &key);
  EVP_PKEY_CTX_free(ctx);
  return key;
}

bool SetKey(BIO *bio, DCRYPT_PKEY *key, bool is_private) {
  int ret = 0;
  if (is_private) {
    ret = PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, 0, NULL);
  } else {
    ret = PEM_write_bio_PUBKEY(bio, key);
  }
  CHECK_NOT_EQUAL(1, ret, "Could not write key to output stream", return false);

  return true;
}

DCRYPT_PKEY *GetKey(BIO *bio, bool is_private) {
  RSA *rsa = NULL;
  if (is_private) {
    PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
  } else {
    PEM_read_bio_RSA_PUBKEY(bio, &rsa, NULL, NULL);
  }
  CHECK_EQUAL(NULL, rsa, "Could not read key from BIO", return NULL);

  EVP_PKEY *key = NULL;
  key = EVP_PKEY_new();
  CHECK_EQUAL(NULL, key, "Could not allocate EVP_PKEY", return NULL);

  EVP_PKEY_assign_RSA(key, rsa);
  return key;
}

bool KeyToFile(DCRYPT_PKEY *key, char *out_file, bool is_private) {
  BIO *file_BIO = NULL;
  file_BIO = BIO_new_file(out_file, "w");
  CHECK_EQUAL(NULL, file_BIO, "Could not load file for writing", return false);

  int ret = SetKey(file_BIO, key, is_private);
  BIO_free(file_BIO);
  CHECK_NOT_EQUAL(true, ret, "Could not write key to file", return false);

  return true;
}

unsigned char *KeyToString(DCRYPT_PKEY *key, bool is_private) {
  int ret = 0;
  BIO *key_BIO = NULL;
  key_BIO = BIO_new(BIO_s_mem());
  CHECK_EQUAL(NULL, key_BIO, "Could not allocate memory for writing",
              return NULL);

  ret = SetKey(key_BIO, key, is_private);
  CHECK_NOT_EQUAL(1, ret, "Could not write key to string", BIO_free(key_BIO);
                  return NULL);

  int key_length = BIO_pending(key_BIO);
  unsigned char *key_string = (unsigned char *)malloc(key_length + 1);
  CHECK_EQUAL(NULL, key_string, "Could not allocate memory for key string",
              return NULL);

  int len = BIO_read(key_BIO, key_string, key_length);
  BIO_free(key_BIO);

  if (len < 1) {
    return NULL;
  }

  return key_string;
}

DCRYPT_PKEY *FileToKey(char *in_file, bool is_private) {
  BIO *file_BIO = NULL;
  file_BIO = BIO_new_file(in_file, "r");
  CHECK_EQUAL(NULL, file_BIO, "Could not open file for reading", return NULL);

  EVP_PKEY *key = NULL;
  key = GetKey(file_BIO, is_private);
  BIO_free(file_BIO);
  CHECK_EQUAL(NULL, key, "Could not get key from file", return NULL);

  return key;
}

DCRYPT_PKEY *StringToKey(unsigned char *key_string, bool is_private) {
  BIO *key_BIO = NULL;
  key_BIO = BIO_new_mem_buf(key_string, -1);
  CHECK_EQUAL(NULL, key_BIO, "Could not allocate memory buffer for string",
              return NULL);

  EVP_PKEY *key = NULL;
  key = GetKey(key_BIO, is_private);
  BIO_free(key_BIO);
  CHECK_EQUAL(NULL, key, "Could not get key from string", return NULL);

  return key;
}

unsigned char *Sign(char *message, DCRYPT_PKEY *key) {
  size_t sig_length;
  EVP_MD_CTX *ctx = NULL;

  ctx = EVP_MD_CTX_create();
  if (ctx == NULL) {
    printf("%s\n", "Could not initialize EVP context");
    return NULL;
  }

  CHECK_MD(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key), return NULL);
  CHECK_MD(EVP_DigestSignUpdate(ctx, message, strlen(message)), return NULL);
  CHECK_MD(EVP_DigestSignFinal(ctx, NULL, &sig_length), return NULL);

  unsigned char *sig = NULL;
  sig = (unsigned char *)malloc(sig_length);
  CHECK_EQUAL(NULL, sig, "Could not allocate memory for signature",
              return NULL);
  CHECK_MD(EVP_DigestSignFinal(ctx, sig, &sig_length), return NULL);

  EVP_MD_CTX_free(ctx);
  return sig;
}

bool Verify(char *message, unsigned char *signature, DCRYPT_PKEY *pubkey) {
  size_t sig_length = 256;
  EVP_MD_CTX *ctx = NULL;

  ctx = EVP_MD_CTX_create();
  if (ctx == NULL) {
    printf("%s\n", "Could not initialize EVP context");
    return false;
  }

  CHECK_MD(EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey),
           return false);
  CHECK_MD(EVP_DigestVerifyUpdate(ctx, message, strlen(message)), return false);
  CHECK_MD(EVP_DigestVerifyFinal(ctx, signature, sig_length), return false);

  EVP_MD_CTX_free(ctx);
  return true;
}

unsigned char *GenerateRandomBytes(int size) {
  unsigned char *bytes = (unsigned char *)malloc(size);
  CHECK_EQUAL(NULL, bytes, "Could not allocate memory for random bytes",
              return NULL);

  int written = RAND_bytes(bytes, size);
  CHECK_NOT_EQUAL(1, written, "Could not generate random bytes", return NULL);

  bytes[size - 1] = '\0';
  return bytes;
}

// TODO generate an AES key, and encrypt/decrypt instead of sign/verify

#ifdef __cplusplus
}  // namespace dcrypt
#endif
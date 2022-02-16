# dcrypt

A utility library that wraps commonly-used cryptographic operations using OpenSSL's libcrypto API

## IMPORTANT
This library was written for the education of the author and as such is absolutely **NOT** production-ready code!

## Install
This library is targeted to Linux only and depends on `libssl`.

The Makefile uses the `clang` compiler and `lld` linker, but can be replaced with `gcc` and `ld` if LLVM tools are not installed.

To download and install, run

```
git clone https://github.com/ddddddeon/dcrypt.git
cd dcrypt
make
sudo make install
```

## Usage
```c
#include <assert.h>
#include <dcrypt.h>

#define KEY_LENGTH 4096

int main(int argc, char *argv[]) {
  // Generate a 4096-bit RSA key
  DCRYPT_PKEY *private_key = RSAGenerateKey(KEY_LENGTH);
  assert(private_key != NULL);

  // Write a private key to PEM-encoded file (private = true)
  bool written = RSAKeyToFile(private_key, "example_rsa", true);
  assert(written == true);

  // Write a public key to PEM-encoded file (private = false)
  written = RSAKeyToFile(private_key, "example_rsa.pub", false);
  assert(written == true);

  // Load a public or private key from PEM-encoded file
  DCRYPT_PKEY *public_key = RSAFileToKey("./example_rsa.pub", false);
  assert(public_key != NULL);

  // Convert a key to string
  unsigned char *public_key_string = RSAKeyToString(public_key, false);
  printf("%s\n", public_key_string);

  // Generate N random bytes
  unsigned char *message = GenerateRandomBytes(32);

  // Sign a message with the private key
  unsigned char *signature = RSASign((char *)message, private_key);
  assert(signature != NULL);

  // Verify a message with the public key
  // Pass in the key length so Verify() knows how big to make the signature
  bool verified = RSAVerify((char *)message, signature, public_key, KEY_LENGTH);
  assert(verified == true);

  // Encrypt a string with the public key
  unsigned char *ciphertext = RSAEncrypt("hello alice", public_key);

  // Decrypt a string with the private key
  unsigned char *plaintext = RSADecrypt(ciphertext, private_key);

  // hello alice
  printf("%s\n", plaintext);

  // Keys, byte arrays & signatures are allocated & must be freed by the
  // caller
  DCRYPT_PKEY_free(private_key);
  DCRYPT_PKEY_free(public_key);
  free(message);
  free(signature);
  free(ciphertext);
  free(plaintext);
}
```

## TODOs
- AES key creation
- Encrypt/Decrypt using AES key
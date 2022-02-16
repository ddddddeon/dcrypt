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
  bool verified = RSAVerify((char *)message, signature, public_key);
  assert(verified == true);

  // Encrypt a string with the public key
  unsigned char *ciphertext = RSAEncrypt("hello alice", public_key);

  // Decrypt a string with the private key
  unsigned char *plaintext = RSADecrypt(ciphertext, private_key);

  // hello alice
  printf("%s\n", plaintext);

  // Keys, byte arrays & signatures are allocated & must be freed by the caller
  DCRYPT_PKEY_free(private_key);
  DCRYPT_PKEY_free(public_key);
  free(public_key_string);
  free(message);
  free(signature);
  free(ciphertext);
  free(plaintext);
}
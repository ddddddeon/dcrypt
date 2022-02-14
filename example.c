#include <assert.h>
#include <dcrypt.h>

#define KEY_LENGTH 4096

int main(int argc, char *argv[]) {
  // Generate a 4096-bit RSA key
  DCRYPT_PKEY *private_key = GenerateKey(KEY_LENGTH);
  assert(private_key != NULL);

  // Write a private key to PEM-encoded file (private = true)
  bool written = KeyToFile(private_key, "example_rsa", true);
  assert(written == true);

  // Write a public key to PEM-encoded file (private = false)
  written = KeyToFile(private_key, "example_rsa.pub", false);
  assert(written == true);

  // Load a public or private key from PEM-encoded file
  DCRYPT_PKEY *public_key = FileToKey("./example_rsa.pub", false);
  assert(public_key != NULL);

  // Convert a key to string
  unsigned char *public_key_string = KeyToString(public_key, false);
  printf("%s\n", public_key_string);

  // Generate N random bytes
  unsigned char *message = GenerateRandomBytes(32);

  // Sign a message with the private key
  unsigned char *signature = Sign((char *)message, private_key);
  assert(signature != NULL);

  // Verify a message with the public key
  // Pass in the key length so Verify() knows how big to make the signature
  bool verified = Verify((char *)message, signature, public_key, KEY_LENGTH);
  assert(verified == true);

  // keys, byte arrays & signatures are allocated & must be freed by the caller
  DCRYPT_PKEY_free(private_key);
  DCRYPT_PKEY_free(public_key);
  free(message);
  free(signature);
}
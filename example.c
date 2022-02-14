#include <assert.h>
#include <dcrypt.h>

int main(int argc, char *argv[]) {
  // Generate a 4096-bit RSA key
  DCRYPT_PKEY *private_key = GenerateKey(2048);
  assert(private_key != NULL);

  // Write a private key to PEM-encoded file (private = true)
  bool written = KeyToFile(private_key, "example_rsa", true);
  assert(written == true);

  written = KeyToFile(private_key, "example_rsa.pub", false);
  assert(written == true);

  // Load a key from file
  DCRYPT_PKEY *loaded_public_key = FileToKey("./example_rsa.pub", false);
  assert(loaded_public_key != NULL);

  unsigned char *loaded_public_key_string =
      KeyToString(loaded_public_key, false);
  printf("%s\n", loaded_public_key_string);
  printf("*****\n");

  // Sign a message with the private key
  char *message = "message to be signed";
  unsigned char *signature = Sign(message, private_key);
  assert(signature != NULL);

  bool verified = Verify(message, signature, loaded_public_key);
  assert(verified == true);

  printf("%d\n", verified);
}
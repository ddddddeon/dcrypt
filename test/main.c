#include <assert.h>
#include <malloc.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <string.h>

#include "../src/dcrypt.h"

int main(int argc, char* argv[]) {
  EVP_PKEY* privkey = GenerateKey(2048);
  assert(privkey != NULL);

  EVP_PKEY* short_privkey = GenerateKey(512);
  assert(short_privkey == NULL);

  EVP_PKEY* long_privkey = GenerateKey(65536);
  assert(long_privkey == NULL);

  unsigned char* privkey_string = KeyToString(privkey, true);
  assert(privkey_string != NULL);

  unsigned char* pubkey_string = KeyToString(privkey, false);
  assert(pubkey_string != NULL);

  EVP_PKEY* pubkey = StringToKey(pubkey_string, false);
  assert(pubkey != NULL);

  unsigned char* pubkey_string2 = KeyToString(pubkey, false);
  assert(pubkey_string2 != NULL);
  assert(strcmp((char*)pubkey_string, (char*)pubkey_string2) == 0);

  assert(KeyToFile(privkey, "id_rsa", true));
  assert(KeyToFile(privkey, "id_rsa.pub", false));

  EVP_PKEY* opened_privkey = FileToKey("./id_rsa", true);
  EVP_PKEY* opened_pubkey = FileToKey("./id_rsa.pub", false);

  assert(opened_privkey != NULL);
  assert(opened_pubkey != NULL);

  unsigned char* opened_privkey_string = KeyToString(opened_privkey, true);
  unsigned char* opened_pubkey_string = KeyToString(opened_pubkey, false);

  assert(opened_privkey_string != NULL);
  assert(opened_pubkey_string != NULL);
  assert(strcmp((char*)privkey_string, (char*)opened_privkey_string) == 0);
  assert(strcmp((char*)pubkey_string, (char*)opened_pubkey_string) == 0);

  printf("%s\n", opened_privkey_string);
  printf("%s\n", opened_pubkey_string);

  char* message = "chris is cool";
  printf("Message: %s\n", message);

  unsigned char* sig = Sign(message, opened_privkey);
  if (sig == NULL) {
    printf("Could not generate signature!\n");
    return false;
  } else {
    printf("Signed message with private key-- signature: %x\n", sig);
  }

  printf("Verifying message with public key...\n");

  bool verified = Verify(message, sig, opened_pubkey);
  if (verified) {
    printf("Verified! Signature is valid for message: %s\n", message);
  } else {
    printf("Not Verified...\n");
    return false;
  }

  unsigned char *sig2 = (unsigned char *) "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf";

  bool verified2 = Verify(message, sig2, opened_pubkey);
  if (verified2) {
    printf("Verified?! This shouldn't succeed...\n");
    return false;
  } else {
    printf("Not verified using bogus signature-- good!\n");
  }

  char* message2 = "chris is not cool?";
  bool verified3 = Verify(message2, sig, opened_pubkey);
  if (verified3) {
    printf("Verified?! This shouldn't succeed...\n");
    return false;
  } else {
    printf("Not verified using bogus message-- good!\n");
  }

  int bytes_length = 32;
  unsigned char* bytes = NULL;
  bytes = GenerateRandomBytes(bytes_length);
  assert(bytes != NULL);
  for (int i = 0; i < bytes_length; i++) {
    printf("%x", (char*)bytes[i]);
  }
  printf("\n");

  unsigned char* bytes2 = NULL;
  bytes2 = GenerateRandomBytes(bytes_length);
  assert(bytes2 != NULL);

  assert(strcmp((char*)bytes2, (char*)bytes) != 0);

  for (int i = 0; i < bytes_length; i++) {
    printf("%x", (char*)bytes2[i]);
  }
  printf("\n");

  free(bytes2);
  free(bytes);
  free(sig);
  free(privkey_string);
  free(pubkey_string);
  free(pubkey_string2);
  EVP_PKEY_free(short_privkey);
  EVP_PKEY_free(privkey);

  return 0;
}

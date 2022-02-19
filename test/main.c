#include <assert.h>
#include <malloc.h>
#include <stdbool.h>
#include <string.h>

#include "../src/dcrypt.h"

#define KEY_LENGTH 2048

int main(int argc, char* argv[]) {
  DCRYPT_PKEY* privkey = RSAGenerateKey(KEY_LENGTH);
  assert(privkey != NULL);

  DCRYPT_PKEY* short_privkey = RSAGenerateKey(512);
  assert(short_privkey == NULL);

  DCRYPT_PKEY* long_privkey = RSAGenerateKey(65536);
  assert(long_privkey == NULL);

  unsigned char* privkey_string = RSAKeyToString(privkey, true);
  assert(privkey_string != NULL);

  unsigned char* pubkey_string = RSAKeyToString(privkey, false);
  assert(pubkey_string != NULL);

  DCRYPT_PKEY* pubkey = RSAStringToKey(pubkey_string, false);
  assert(pubkey != NULL);

  unsigned char* pubkey_string2 = RSAKeyToString(pubkey, false);
  assert(pubkey_string2 != NULL);
  assert(strcmp((char*)pubkey_string, (char*)pubkey_string2) == 0);

  assert(RSAKeyToFile(privkey, "id_rsa", true));
  assert(RSAKeyToFile(privkey, "id_rsa.pub", false));

  DCRYPT_PKEY* opened_privkey = RSAFileToKey("./id_rsa", true);
  DCRYPT_PKEY* opened_pubkey = RSAFileToKey("./id_rsa.pub", false);

  assert(opened_privkey != NULL);
  assert(opened_pubkey != NULL);

  unsigned char* opened_privkey_string = RSAKeyToString(opened_privkey, true);
  unsigned char* opened_pubkey_string = RSAKeyToString(opened_pubkey, false);

  assert(opened_privkey_string != NULL);
  assert(opened_pubkey_string != NULL);
  assert(strcmp((char*)privkey_string, (char*)opened_privkey_string) == 0);
  assert(strcmp((char*)pubkey_string, (char*)opened_pubkey_string) == 0);

  printf("%s\n", opened_privkey_string);
  printf("%s\n", opened_pubkey_string);

  char* message = "chris is cool";
  printf("Message: %s\n", message);

  unsigned char* sig = RSASign(message, opened_privkey);
  if (sig == NULL) {
    printf("Could not generate signature!\n");
    assert(false);
  } else {
    printf("Signed message with private key-- signature: %s\n", sig);
  }

  printf("Verifying message with public key...\n");

  bool verified = RSAVerify(message, sig, opened_pubkey);
  if (verified) {
    printf("Verified! Signature is valid for message: %s\n", message);
  } else {
    printf("Not Verified...\n");
    assert(false);
  }

  unsigned char *sig2 = (unsigned char *) "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf";

  bool verified2 = RSAVerify(message, sig2, opened_pubkey);
  if (verified2) {
    printf("Verified?! This shouldn't succeed...\n");
    assert(false);
  } else {
    printf("Not verified using bogus signature-- good!\n");
  }

  char* message2 = "chris is not cool?";
  bool verified3 = RSAVerify(message2, sig, opened_pubkey);
  if (verified3) {
    printf("Verified?! This shouldn't succeed...\n");
    assert(false);
  } else {
    printf("Not verified using bogus message-- good!\n");
  }

  int bytes_length = 32;
  unsigned char* bytes = NULL;
  bytes = GenerateRandomBytes(bytes_length);
  assert(bytes != NULL);
  for (int i = 0; i < bytes_length; i++) {
    printf("%x", (unsigned int)bytes[i]);
  }
  printf("\n");

  unsigned char* bytes2 = NULL;
  bytes2 = GenerateRandomBytes(bytes_length);
  assert(bytes2 != NULL);

  assert(strcmp((char*)bytes2, (char*)bytes) != 0);

  for (int i = 0; i < bytes_length; i++) {
    printf("%x", (unsigned int)bytes2[i]);
  }
  printf("\n");

  unsigned char* ciphertext = RSAEncrypt("chris is cool", pubkey);
  unsigned char* plaintext = RSADecrypt(ciphertext, privkey);
  printf("%s\n", plaintext);

  unsigned char* plaintext2 = RSADecrypt(ciphertext, pubkey);
  if (plaintext2 == NULL) {
    printf("Couldn't RSA decrypt ciphertext using only public key-- good!\n");
  } else {
    printf("Somehow RSA decrypted ciphertext with only public key\n");
    assert(false);
  }

  unsigned char* ciphertext2 = RSAEncrypt((char*)sig2, pubkey);
  if (ciphertext2 == NULL) {
    printf(
        "Didn't try to RSA encrypt plaintext longer than the key length-- "
        "good!\n");
  } else {
    printf("Tried to RSA encrypt plaintext longer than the key length\n");
    assert(false);
  }

  int key_size = RSAKeySize(pubkey);
  printf("%d\n", key_size);

  free(ciphertext2);
  free(plaintext2);
  free(plaintext);
  free(ciphertext);
  free(bytes2);
  free(bytes);
  free(sig);
  free(privkey_string);
  free(pubkey_string);
  free(pubkey_string2);
  free(opened_pubkey_string);
  free(opened_privkey_string);
  DCRYPT_PKEY_free(opened_pubkey);
  DCRYPT_PKEY_free(opened_privkey);
  DCRYPT_PKEY_free(pubkey);
  DCRYPT_PKEY_free(privkey);

  return 0;
}

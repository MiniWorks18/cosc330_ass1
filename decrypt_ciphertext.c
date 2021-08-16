/******************************************************************************
 * decrypt_ciphertext.c
 * Simple program that demonstrates the use of the openSSL library functions to 
 * decrypt a simple text with an Advanced Encryption Standard (AES) cipher 
 * algorithm. AES is a block cipher algorithm used to encrypt data using 
 * symmetric 128, 192 or 256-bit keys.
 * 
 * TODO: Additional error checking - for full marks, you solution will need
 * to check the returns of all functions and take sensible actions.
 * 
 * Cyptertext is printed to the terminal.
 * 
 * Parameters:
 *     1. The key to use for decryption
 * 
 * Returns: 0 on Success
 * 
 * Build: 
 *     gcc -Wall -pedantic -lcrypto generate_ciphertext.c -o 
 *        generate_ciphertext
 * Run Example:
 *     generate_ciphertext 12345678123456781234567812345678
 * ***************************************************************************/

/* Libraries for I/O and Standard functions*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
/* OpenSSL libraries - don;t forget -lcypto to link the binaries at 
compilation*/
#include <openssl/evp.h>
#include <openssl/aes.h>

/*****************************************************************************
 * Function: aes_init
 * 
 * Initialises the aes encryption struct using the proveded key, key length,
 * and the EVP_aes_256_cbc() mode.
 * 
 * Parameters: 
 *     unsigned char *key_data - Pointer to the Key
 *     int key_data_len - The length of the key 
 *     EVP_CIPHER_CTX *e_ctx - Pointer to the encryption device
 *     EVP_CIPHER_CTX *d_ctx - Pointer to the decryption device
 * 
 * Returns: 0 on Success (TODO: additional error checking)
 ****************************************************************************/
int
aes_init (unsigned char *key_data,
	  int key_data_len, EVP_CIPHER_CTX * e_ctx, EVP_CIPHER_CTX * d_ctx)
{

  int i;
  unsigned char key[32], iv[32];

  //Only use most significant 32 bytes of data if > 32 bytes
  if (key_data_len > 32)
    key_data_len = 32;

  //Copy bytes to the front of the key array
  for (i = 0; i < key_data_len; i++)
    {
      //In a real-word solution, the key would be filled with a random
      //stream of bytes - we are taking a shortcut because encryption
      //is not the focus of this unit.
      key[i] = key_data[i];
      iv[i] = key_data[i];
    }

  //Pad out to 32 bytes if key < 32 bytes
  for (i = key_data_len; i < 32; i++)
    {
      key[i] = 0;
      iv[i] = 0;
    }
  //Create and initialize the encryption device.
  EVP_CIPHER_CTX_init (e_ctx);
  EVP_EncryptInit_ex (e_ctx, EVP_aes_256_cbc (), NULL, key, iv);
  EVP_CIPHER_CTX_init (d_ctx);
  EVP_DecryptInit_ex (d_ctx, EVP_aes_256_cbc (), NULL, key, iv);

  return 0;
}

/*
 * Decrypt *len bytes of ciphertext
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *
aes_decrypt (EVP_CIPHER_CTX * e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext */
  int p_len = *len, f_len = 0;

  //Allocate a block of memory to store the plain text.
  //WATCH-OUT: you need to remember to de-allocate this when you are finished 
  //with the plain text, otherwise you may create a memory leak.
  unsigned char *plaintext = malloc (p_len);

  // Allows reusing of 'e' for multiple decryption cycles
  EVP_DecryptInit_ex (e, NULL, NULL, NULL, NULL);

  // update plaintest, p_len is filled with the length of plaintext generated,
  // len is the size of ciphertext in bytes
  EVP_DecryptUpdate (e, plaintext, &p_len, ciphertext, *len);
  // Update plaintext with the final remaining bytes
  EVP_DecryptFinal_ex (e, plaintext + p_len, &f_len);
  //return the results
  return plaintext;
}

/*****************************************************************************
 * Function: main
 * 
 * Main program to demonstrate simplified AES encryption on a simple text
 * file. The demo program only has limited error checking.  
 * 
 * TODO: Additional error checking and error returns.
 * TODO: Dynamic sizing and memory allocation of elements.
 * TODO: Comprehensive error checking.
 * 
 * Parameters: 
 *     1. The key to use for encryption
 *     2. The file name for the cipher text file 
 * 
 * Returns: 0 on Success, Ciphertext printed to stdout
 * 
 ****************************************************************************/
int
main (int argc, char **argv)
{

  // "opaque" encryption, decryption ctx structures that libcrypto 
  // uses to record status of enc/dec operations
  EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new ();
  EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new ();

  unsigned char *key_data;
  int key_data_len;
  int len, clen;
  char *plaintext;

  //Read in the ciphertext
  //TODO: Make this more dynamic, size, filename etc.
  //TODO: Implement basic error checking :(
  FILE *myfile;
  myfile = fopen (argv[2], "r");
  fseek (myfile, 0, SEEK_END);
  clen = ftell (myfile);
  rewind (myfile);
  unsigned char cipher_in[clen];
  fread (cipher_in, clen, 1, myfile);
  fclose (myfile);

  // the key_data is read from the argument list
  key_data = (unsigned char *) argv[1];
  key_data_len = strlen (argv[1]);

  printf ("This is the key: %s \n", key_data);
  printf ("It is %d bytes in length\n", key_data_len);

  if (aes_init (key_data, key_data_len, en, de))
    {
      printf ("Couldn't initialize AES cipher\n");
      return -1;
    }

  //Print cipher out to console - here I use pringf so it might 
  //cut off if there is a '\0' character

  printf ("Ciphertext: %s\n", (char *) cipher_in);

  // Equivalent to strlen() for byte buffer(unsigned char array)
  len = sizeof (cipher_in) / sizeof (cipher_in[0]);
  plaintext = (char *) aes_decrypt (de, (unsigned char *) cipher_in, &len);
  printf ("Plaintext: %s\n", plaintext);

  //Dealocate the dynamically created heap memory items. 
  free (plaintext);
  EVP_CIPHER_CTX_free (en);
  EVP_CIPHER_CTX_free (de);

  return 0;
}

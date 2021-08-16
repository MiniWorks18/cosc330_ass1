
/******************************************************************************
 * generate_ciphertext.c
 * Simple program that demonstrates the use of the openSSL library functions to 
 * encrypt simple text with an Advanced Encryption Standard (AES) cipher 
 * algorithm. AES is a block cipher algorithm used to encrypt data using 
 * symmetric 128, 192 or 256-bit keys.
 * 
 * TODO: Additional error checking - for full marks, you solution will need
 * to check the returns of all functions and take sensible actions.
 * 
 * Cyptertext is printed to the terminal.
 * 
 * Parameters:
 *     1. The key to use for encryption
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

/*****************************************************************************
 * Function: aes_encrypt
 * 
 * Uses and initialized AES encryption device to encrypt len bytes of 
 * plaintext. 
 * 
 * Parameters: 
 *     EVP_CIPHER_CTX *e_ctx - Pointer to the encryption device
 *     unsigned char *plaintext - Pointer to the plaintext
 *     int *len - Pointer to the length of plaintext
 * 
 * Returns: unsigned char * - Pointer to encrypted bytes
 * 
 * TODO: additional error checking and error returns.
 * 
 ****************************************************************************/
unsigned char *
aes_encrypt (EVP_CIPHER_CTX * e, unsigned char *plaintext, int *len)
{
  // Max ciphertext len for 'n' bytes of plaintext is n + 
  //AES_BLOCK_SIZE -1 bytes
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;

  //Allocate a block of memory to store the cyphertext.
  //WATCH-OUT: you need to remember to de-allocate this when you are 
  //finished with the cyphertext, otherwise you may create a memory leak.
  unsigned char *ciphertext = malloc (c_len);

  // Allows reusing of 'e' for multiple encryption cycles
  EVP_EncryptInit_ex (e, NULL, NULL, NULL, NULL);

  // update ciphertext, c_len is filled with the length of ciphertext 
  //generated, len is the size of plaintext in bytes
  EVP_EncryptUpdate (e, ciphertext, &c_len, plaintext, *len);

  // Update ciphertext with the final remaining bytes
  EVP_EncryptFinal_ex (e, ciphertext + c_len, &f_len);

  //Update len to reflect the actual length of the cipher after encryption.
  //Cipher-Block-Chaining algorithm will result in block-multiple sized
  //ciphertext.
  //TODO: Read about Cipher-Block-Chaining
  *len = c_len + f_len;
  return ciphertext;
}

/*****************************************************************************
 * Function: main
 * 
 * Main program to demonstrate simplified AES encryption on a simple text
 * file. The demo program only has limited error chec  
 * 
 * TODO: Additional error checking and error returns.
 * TODO: Dynamic sizing and memory allocation of elements.
 * TODO: Comprehensive error checking.
 * 
 * Parameters: 
 *     1. The key to use for encryption  
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

  //Pointer to the key 
  unsigned char *key_data;
  //Length of the key
  int key_data_len;

  //Lengths used to process plaintext
  int len, plen;
  unsigned char *ciphertext;

  //Read in the plaintext
  //TODO: Make this more dynamic, size, filename etc.
  //TODO: Implement basic error checking :(

  FILE *myplainfile;
  myplainfile = fopen (argv[2], "r");
  fseek (myplainfile, 0, SEEK_END);
  plen = ftell (myplainfile);
  rewind (myplainfile);
  char plainText[plen];
  fread (plainText, plen, 1, myplainfile);
  fclose (myplainfile);

  //the key_data is read from the argument list
  key_data = (unsigned char *) argv[1];
  key_data_len = strlen (argv[1]);

  if (aes_init (key_data, key_data_len, en, de))
    {
      printf ("Couldn't initialize AES cipher\n");
      return -1;
    }

  /* The enc/dec functions deal with binary data and not C strings. strlen() 
     will return length of the string without counting the '\0' string marker. 
     We always pass in the marker byte to the encrypt/decrypt functions so 
     that after decryption we end up with a legal C string */
  len = sizeof (plainText) / sizeof (plainText[0]) + 1;

  //Encrypt the plain text
  ciphertext = aes_encrypt (en, (unsigned char *) plainText, &len);

  //print cipher bytes to stdout byte-by-byte
  //I don't trust printf("%s"....) to do this correctly due to
  //the potential of '\0' (NULL) characters in the cipher stream.
  //This will look very messy as there will still be non-printables in there. 
  int cipher_length = len;
  int cp = 0;
  for (cp = 0; cp < cipher_length; cp++)
    {
      printf ("%c", ciphertext[cp]);
    }

  //Dealocate the dynamically created heap memory items. 
  free (ciphertext);
  EVP_CIPHER_CTX_free (en);
  EVP_CIPHER_CTX_free (de);

  return 0;
}

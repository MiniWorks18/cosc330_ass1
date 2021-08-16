/******************************************************************************
 * search_keyspace.c
 * Simple program that demonstrates the use of the openSSL library functions
 * to brute-force search for an AES encryption key given a partial key. This
 * is a simple single-process version that demonstrates the operations needed
 * to complete the 
 * 
 * TODO: Additional error checking - for full marks, you solution will need
 * to check the returns of all functions and take sensible actions.
 * 
 * Cyptertext is printed to the terminal.
 * 
 * Parameters:
 *     1. The partial key to use for the search
 * 
 * Returns: 0 on Success
 * 
 * Build: 
 *     gcc -Wall -pedantic -lcrypto generate_ciphertext.c -o 
 *        generate_ciphertext
 * Run Example:
 *     generate_ciphertext 12345678123456781234567812345678
 * ***************************************************************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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
 * ***************************************************************************/
int
aes_init (unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX * e_ctx,
	  EVP_CIPHER_CTX * d_ctx)
{

  int i;
  unsigned char key[32], iv[32];
  //Some robust programming to start with
  //Only use most significant 32 bytes of data if > 32 bytes
  if (key_data_len > 32)
    key_data_len = 32;

  //In a real-word solution, the key would be filled with a random
  //stream of bytes - we are taking a shortcut because encryption
  //is not the focus of this unit.
  for (i = 0; i < key_data_len; i++)
    {
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
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc (p_len);

  EVP_DecryptInit_ex (e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate (e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex (e, plaintext + p_len, &f_len);

  return plaintext;
}

/*****************************************************************************
 * Function: main
 * 
 * Main program to demonstrate a simplified AES key search using a single
 * process.   
 * 
 * TODO: Additional error checking and error returns.
 * TODO: Dynamic sizing and memory allocation of elements.
 * TODO: Comprehensive error checking.
 * 
 * Parameters: 
 *     1. The key to use for encryption
 *     2. The name for the cipher text file
 *     3. The name for the plain text file 
 * 
 * Returns: 0 on Success, key printed to stdout
 * 
 ****************************************************************************/
int
main (int argc, char **argv)
{

  //Pointers to key data location
  unsigned char *key_data;
  //Key length
  int key_data_len, i;
  //Pointer to plain text
  char *plaintext;

  unsigned char key[32];
  unsigned char trialkey[32];

  int cipher_length, plain_length;

  key_data = (unsigned char *) argv[1];
  key_data_len = strlen (argv[1]);

  // Read encrypted bytes from file
  //TODO: Make this more dynamic
  FILE *mycipherfile;
  mycipherfile = fopen (argv[2], "r");
  fseek (mycipherfile, 0, SEEK_END);
  cipher_length = ftell (mycipherfile);
  rewind (mycipherfile);
  unsigned char cipher_in[cipher_length];
  fread (cipher_in, cipher_length, 1, mycipherfile);
  fclose (mycipherfile);

  // Read decrypted bytes(to cross reference key results) from file
  FILE *myplainfile;
  myplainfile = fopen (argv[3], "r");
  fseek (myplainfile, 0, SEEK_END);
  plain_length = ftell (myplainfile);
  rewind (myplainfile);
  char plain_in[plain_length];
  fread (plain_in, plain_length, 1, myplainfile);
  fclose (myplainfile);

  //printf("Plaintext: %s\n\n", (char*)plain_in);
  int y;
  printf ("\nPlain:");
  for (y = 0; y < plain_length; y++)
    {
      printf ("%c", plain_in[y]);
    }
  printf ("\n");

  printf ("Ciphertext: %s\n\n", (char *) cipher_in);

  //Condition known portion of key
  //Only use most significant 32 bytes of data if > 32 bytes
  if (key_data_len > 32)
    key_data_len = 32;

  //Copy bytes to the front of the key array
  for (i = 0; i < key_data_len; i++)
    {
      key[i] = key_data[i];
      trialkey[i] = key_data[i];
    }

  //If the key data < 32 bytes, pad the remaining bytes with 0s
  for (i = key_data_len; i < 32; i++)
    {
      key[i] = 0;
      trialkey[i] = 0;
    }

  //This code packs the last 8 individual bytes of the key into an
  //unsigned long-type variable that can be easily incremented 
  //to test key values.
  unsigned long keyLowBits = 0;
  keyLowBits = ((unsigned long) (key[24] & 0xFFFF) << 56) |
    ((unsigned long) (key[25] & 0xFFFF) << 48) |
    ((unsigned long) (key[26] & 0xFFFF) << 40) |
    ((unsigned long) (key[27] & 0xFFFF) << 32) |
    ((unsigned long) (key[28] & 0xFFFF) << 24) |
    ((unsigned long) (key[29] & 0xFFFF) << 16) |
    ((unsigned long) (key[30] & 0xFFFF) << 8) |
    ((unsigned long) (key[31] & 0xFFFF));

  int trial_key_length = 32;
  unsigned long maxSpace = 0;

  //Work out the maximum number of keys to test
  maxSpace =
    ((unsigned long) 1 << ((trial_key_length - key_data_len) * 8)) - 1;
  unsigned long counter;
  fprintf(stderr, "Max space: %ld", maxSpace);

  //Iterate over total number of unknown permutations
  //Hint - Divide this space over the processes
  //(can divide/assign permutations by methods other than 
  //bitwise operations if desired)

  //TODO: This is the processing that needs to be parallelized.
  //The processing in this loop needs to be divided based upon the
  //number of processes used.
  for (counter = 0; counter < maxSpace; counter += 3)
    {
      //OR the low bits of the key with the counter to get next test key
      unsigned long trialLowBits = keyLowBits | counter;
      //Unpack these bits into the end of the trial key array
      trialkey[25] = (unsigned char) (trialLowBits >> 48);
      trialkey[26] = (unsigned char) (trialLowBits >> 40);
      trialkey[27] = (unsigned char) (trialLowBits >> 32);
      trialkey[28] = (unsigned char) (trialLowBits >> 24);
      trialkey[29] = (unsigned char) (trialLowBits >> 16);
      trialkey[30] = (unsigned char) (trialLowBits >> 8);
      trialkey[31] = (unsigned char) (trialLowBits);

      //Set up the encryption device
      EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new ();
      EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new ();

      //Initialise the encryption device
      if (aes_init (trialkey, trial_key_length, en, de))
	{
	  printf ("Couldn't initialize AES cipher\n");
	  return -1;
	}

      // Test permutation of the key to see if we get the desired plain text
      plaintext = (char *) aes_decrypt (de,
					(unsigned char *) cipher_in,
					&cipher_length);

      // Cleanup Cipher Allocated memory
      EVP_CIPHER_CTX_cleanup (en);
      EVP_CIPHER_CTX_cleanup (de);
      EVP_CIPHER_CTX_free (en);
      EVP_CIPHER_CTX_free (de);

      //Key match checking
      //Hint - If key is found(decrypted string matches) return 
      //value back to parent
      if (strncmp (plaintext, plain_in, plain_length) == 0)
	{
	  printf ("\nOK: enc/dec ok for \"%s\"\n", plaintext);
	  printf ("Key No.:%ld:", counter);

	  //Hint - Won't print here(print in parent process)
	  int y;
	  for (y = 0; y < 32; y++)
	    {
	      printf ("%c", trialkey[y]);
	    }

	  printf ("\n");
	  break;
	}

      free (plaintext);
      /*
         Hint - In child processes make sure to release allocated memory and 
         if key found return key to parent.
         Lastly have parent display results.
       */

    }
}

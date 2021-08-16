/***************************************************************************
 * Author: Tully McDonald
 * Date: 15/07/2021
 * In coordination with: The University of New England
 *
 * Program:
 * parallel_search_keyspace.c
 *
 * Purpose:
 *  This program is designed to utilise parallel processing for brute force
 *  attacks on AES keys given that you have access to some of the key,
 *  a piece of decrypted cipher and it's corresponding cipher.
 * 
 * Arguments:
 *  nprocs - Number of processes to place on the ring
 *  partial_key - Some of the start of the key you're trying to brute force
 *  cipher_file - The cipher text in a file
 *  plain_file - The corresponding plain text in a file
 * 
 * Compile:
 *  gcc -Wall -lcrypto parallel_search_keyspace.c -o parallel_search_keyspace
 *
 ***************************************************************************/

#include <stdio.h>     /* for fprintf  */
#include <stdlib.h>    /* for exit     */
#include <unistd.h>    /* for fork     */
#include <string.h>    /* for strtok   */
#include <openssl/evp.h>
#include <openssl/aes.h>
#define BUFFSIZE 50

/*
    Confirms proper command arguments
*/
int parse_args(int argc,  char *argv[ ], int *np){
  if ( (argc != 5) || ((*np = atoi (argv[1])) <= 0) || atoi(argv[1]) <= 1) {
    fprintf (stderr, 
    "Usage: %s nprocs(>1) partial_key cipher_file plain_file\n", argv[0]);
    return(-1); };
  return(0); 
}

/*
    Initiates ring of processes
*/
int make_trivial_ring(){   
  int   fd[2];
  if (pipe (fd) == -1) 
    return(-1); 
  if ((dup2(fd[0], STDIN_FILENO) == -1) ||
      (dup2(fd[1], STDOUT_FILENO) == -1)) 
    return(-2); 
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1))   
    return(-3); 
  return(0); 
}

/*
 *  Adds new processes to the ring
 */
int add_new_node(int *pid){
  int fd[2];
  if (pipe(fd) == -1) 
    return(-1); 
  if ((*pid = fork()) == -1)
    return(-2); 
  if(*pid > 0 && dup2(fd[1], STDOUT_FILENO) < 0)
    return(-3); 
  if (*pid == 0 && dup2(fd[0], STDIN_FILENO) < 0)
    return(-4); 
  if ((close(fd[0]) == -1) || (close(fd[1]) == -1)) 
    return(-5);
  return(0);
}

/*
 *   Initialises the AES encryption struct using OpenSSL
 *
 *   Parameters: 
 *     unsigned char *key_data - Pointer to the Key
 *     int key_data_len - The length of the key 
 *     EVP_CIPHER_CTX *e_ctx - Pointer to the encryption device
 *     EVP_CIPHER_CTX *d_ctx - Pointer to the decryption device
 *  
 *   Returns 0 on success
 */
int aes_init (unsigned char *key_data, int key_data_len, 
    EVP_CIPHER_CTX * e_ctx, EVP_CIPHER_CTX * d_ctx) {

  int i;
  unsigned char key[32], iv[32];
  // Some robust programming to start with
  // Only use most significant 32 bytes of data if > 32 bytes
  if (key_data_len > 32)
    key_data_len = 32;

  // In a real-word solution, the key would be filled with a random
  // stream of bytes - we are taking a shortcut because encryption
  // is not the focus of this unit.
  for (i = 0; i < key_data_len; i++)
    {
      key[i] = key_data[i];
      iv[i] = key_data[i];
    }
  // Pad out to 32 bytes if key < 32 bytes
  for (i = key_data_len; i < 32; i++)
    {
      key[i] = 0;
      iv[i] = 0;
    }
  // Create and initialize the encryption device.
  if (!EVP_CIPHER_CTX_init (e_ctx)) return -1;
  if (!EVP_EncryptInit_ex (e_ctx, EVP_aes_256_cbc (), NULL, key, iv)) 
    return -2;
  if (!EVP_CIPHER_CTX_init (d_ctx)) return -3;
  if (!EVP_DecryptInit_ex (d_ctx, EVP_aes_256_cbc (), NULL, key, iv)) 
    return -4;

  return 0;
}

/*
 * Decrypts a cipher with provides parameters
 * 
 * Parameters:
 *   EVP_CIPHER_CTX *e - pointer to the key
 *   unsigned char * ciphertext - pointer to the cipher
 *   int *len - length of the results
 * 
 * Returns the plaintext result
 */
unsigned char *aes_decrypt (EVP_CIPHER_CTX * e, 
                unsigned char *ciphertext, int *len) {
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc (p_len);

  EVP_DecryptInit_ex (e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate (e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex (e, plaintext + p_len, &f_len);

  return plaintext;
}

/*
 *  Main function 
 * 
 *  Handles parallel processes in ring formation and returns results to
 *  the master process.
 */
int main(int argc, char **argv) {
    int nprocs; // Total number of processes in ring
    int i; // Number of this process
    int childpid; // Indicates process should spawn another
    char buff[BUFFSIZE];
    // Pointers to key data location
    unsigned char *key_data;
    // Key length
    int key_data_len;
    // Pointer to plain text
    char *plaintext;
    int found = 0;
    unsigned long start;

    unsigned char key[32];
    unsigned char trialkey[32];

    int cipher_length, plain_length;

    key_data = (unsigned char *) argv[2];
    key_data_len = strlen (argv[2]);

    if (parse_args(argc, argv, &nprocs) < 0) exit(EXIT_FAILURE);

    // Read encrypted bytes from file
    FILE *mycipherfile;
    if (!(mycipherfile = fopen (argv[3], "r"))) {
        printf("Could not open cipherfile\n");
        exit(EXIT_FAILURE);
    }
    fseek (mycipherfile, 0, SEEK_END);
    if ((cipher_length = ftell (mycipherfile)) < 1) {
        printf("Cipherfile empty\n");
        exit(EXIT_FAILURE);
    }
    rewind (mycipherfile);
    unsigned char cipher_in[cipher_length];
    fread (cipher_in, cipher_length, 1, mycipherfile);
    fclose (mycipherfile);

    // Read decrypted bytes(to cross reference key results) from file
    FILE *myplainfile;
    if (!(myplainfile = fopen (argv[4], "r"))) {
        printf("Could not open plainfile\n");
        exit(EXIT_FAILURE);
    }
    fseek (myplainfile, 0, SEEK_END);
    if ((plain_length = ftell (myplainfile)) < 1) {
        printf("Plainfile empty\n");
        exit(EXIT_FAILURE);
    }
    rewind (myplainfile);
    char plain_in[plain_length];
    fread (plain_in, plain_length, 1, myplainfile);
    fclose (myplainfile);

    int y;
    printf ("\nPlain:");
    for (y = 0; y < plain_length; y++) {
        printf ("%c", plain_in[y]);
    }
    printf ("\n");

    printf ("Ciphertext: %s\n\n", (char *) cipher_in);

    // Condition known portion of key
    // Only use most significant 32 bytes of data if > 32 bytes
    if (key_data_len > 32)
        key_data_len = 32;

    // Copy bytes to the front of the key array
    for (i = 0; i < key_data_len; i++)
        {
        key[i] = key_data[i];
        trialkey[i] = key_data[i];
        }

    // If the key data < 32 bytes, pad the remaining bytes with 0s
    for (i = key_data_len; i < 32; i++)
        {
        key[i] = 0;
        trialkey[i] = 0;
        }

    // This code packs the last 8 individual bytes of the key into an
    // unsigned long-type variable that can be easily incremented 
    // to test key values.
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

    // Work out the maximum number of keys to test
    maxSpace =
        ((unsigned long) 1 << ((trial_key_length - key_data_len) * 8)) - 1;
    unsigned long counter;
    unsigned long j;
    fprintf(stderr, "Number of posibilities: %ld\n", maxSpace);

    start = time(NULL); 

    if(make_trivial_ring() < 0){
        perror("Could not make trivial ring");
        exit(EXIT_FAILURE); };
    for (i = 1; i < nprocs;  i++) {
        if(add_new_node(&childpid) < 0){
            perror("Could not add new node to ring");
            exit(EXIT_FAILURE); 
        };
        if (childpid) break; };

    if (i == 1) { // Master
        read(STDIN_FILENO, buff, BUFFSIZE);
        fprintf(stderr, "\nFull key: %s\n\n", buff);
        fprintf(stderr, "Time: %ld seconds\n", 
            (unsigned long)time(NULL)-start);
    } else { // Workers
        for (counter = 0, j = 0; counter < maxSpace; counter = j*nprocs+(i-1),
            j++) {
        // OR the low bits of the key with the counter to get next test key
        unsigned long trialLowBits = keyLowBits | counter;
        // Unpack these bits into the end of the trial key array
        trialkey[25] = (unsigned char) (trialLowBits >> 48);
        trialkey[26] = (unsigned char) (trialLowBits >> 40);
        trialkey[27] = (unsigned char) (trialLowBits >> 32);
        trialkey[28] = (unsigned char) (trialLowBits >> 24);
        trialkey[29] = (unsigned char) (trialLowBits >> 16);
        trialkey[30] = (unsigned char) (trialLowBits >> 8);
        trialkey[31] = (unsigned char) (trialLowBits);

        // Set up the encryption device
        EVP_CIPHER_CTX *en = EVP_CIPHER_CTX_new ();
        EVP_CIPHER_CTX *de = EVP_CIPHER_CTX_new ();

        // Initialise the encryption device
        if (aes_init (trialkey, trial_key_length, en, de)) {
            printf ("Couldn't initialize AES cipher\n");
            return -1;
        }

        // Test permutation of the key to see if we get the desired plain text
        (plaintext = (char *) aes_decrypt (de, (unsigned char *) cipher_in, 
            &cipher_length));

        // Cleanup Cipher Allocated memory
        EVP_CIPHER_CTX_cleanup (en);
        EVP_CIPHER_CTX_cleanup (de);
        EVP_CIPHER_CTX_free (en);
        EVP_CIPHER_CTX_free (de);

        // Key match checking
        if (strncmp (plaintext, plain_in, plain_length) == 0) {
            found = 1;
            write(STDOUT_FILENO, trialkey, 32);
            free(plaintext);
            break;
        }
        free (plaintext);
        }

        if (!found) {
            if (i == 2) write(STDOUT_FILENO, "NULL", strlen("NULL"));
            read(STDIN_FILENO, buff, sizeof(buff));
            write(STDOUT_FILENO, buff, BUFFSIZE);
        }
    }

    return 0;
}
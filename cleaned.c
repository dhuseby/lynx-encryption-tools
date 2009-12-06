#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sizes.h"
#include "keys.h"
#include "loaders.h"

#define CHUNK_LENGTH (51)
#define min(x,y) ((x < y) ? x : y)

/* helper function for dumping out blocks of data in a human readable form */
void print_data(const unsigned char * data, int size)
{
    int i = 0;
    int j, count;
    int left = size;

    while(i < size)
    {
        count = min(8, (size - i));

        printf("    ");
        for(j = 0; j < count; j++)
        {
            printf("0x%02x, ", data[i + j]);
        }
        printf("\n");
        i += count;
    }
}

void print_data_reverse(const unsigned char * data, int size)
{
    int i;
    unsigned char * tmp = calloc(1, size);
    unsigned char * p = tmp;

    for(i = size - 1; i >= 0; i--)
    {
        (*p) = data[i];
        p++;
    }

    print_data(tmp, size);
    free(tmp);
}


/* result = 2 * result */
void double_value(unsigned char *result, const int length)
{
    int i, x;

    x = 0;
    for (i = length - 1; i >= 0; i--) 
    {
	    x += 2 * result[i];
	    result[i] = (unsigned char) (x & 0xFF);
	    x >>= 8;
    }
    /* shouldn't carry */
}

/* result -= value */
int minus_equals_value(unsigned char *result, 
                       const unsigned char *value, 
                       const int length)
{
    int i, x;
    unsigned char *tmp;

    /* allocate temporary buffer */
    tmp = calloc(1, length);

    x = 0;
    for (i = length - 1; i >= 0; i--) 
    {
	    x += result[i] - value[i];
	    tmp[i] = (unsigned char) (x & 0xFF);
	    x >>= 8;
    }

    if (x >= 0) 
    {
        /* move the result back to BB */
        memcpy(result, tmp, length);
        
        /* free the temporary buffer */
        free(tmp);

        /* this had a carry */
        return 1;
    }

    /* free the temporary buffer */
    free(tmp);

    /* this didn't carry */
    return 0;
}

/* result += value */
void plus_equals_value(unsigned char *result, 
                       const unsigned char *value, 
                       const int length)
{
    int i, tmp;
    int carry = 0;

    for(i = length - 1; i >= 0; i--) 
    {
	    tmp = result[i] + value[i] + carry;
	    if (tmp >= 256)
	        carry = 1;
	    else
	        carry = 0;
	    result[i] = (unsigned char) (tmp);
    }
}

/* L = M * N mod modulus */
void lynx_mont(unsigned char *L,            /* result */
               const unsigned char *M,      /* original chunk of encrypted data */
               const unsigned char *N,      /* copy of encrypted data */
               const unsigned char *modulus,/* modulus */
		       const int length)
{
    int i, j;
    int carry;
    unsigned char tmp;
    unsigned char increment;

    /* L = 0 */
    memset(L, 0, length);

    for(i = 0; i < length; i++)
    {
        /* get the next byte from N */
	    tmp = N[i];

        for(j = 0; j < 8; j++) 
        {
            /* L = L * 2 */
	        double_value(L, length);

	        /* carry is true if the MSB in tmp is set */
            increment = (tmp & 0x80) / 0x80;

            /* shift tmp's bits to the left by one */
	        tmp <<= 1;
	   
            if(increment != 0) 
            {
                /* increment the result... */
                /* L += M */
		        plus_equals_value(L, M, length);

                /* do a modulus correction */
                /* L -= modulus */
                carry = minus_equals_value(L, modulus, length);

                /* if there was a carry, do it again */
                /* L -= modulus */
                if (carry != 0)
                    minus_equals_value(L, modulus, length);
            } 
            else
            {
                /* instead decrement the result */

                /* L -= modulus */
                minus_equals_value(L, modulus, length);
            }
        }
    }
}


/* this decrypts a single block of encrypted data by using the montgomery
 * multiplication method to do modular exponentiation.
 */
int decrypt_block(int accumulator,
                  unsigned char * result,
                  const unsigned char * encrypted,
                  const unsigned char * public_exp,
                  const unsigned char * public_mod,
                  const int length)
{
    int i;
    unsigned char* rptr = result;
    const unsigned char* eptr = encrypted;
    unsigned char *A;
    unsigned char *B;
    unsigned char *TMP;

    /* allocate the working buffers */
    A = calloc(1, length);
    B = calloc(1, length);
    TMP = calloc(1, length);

    /* this copies the next length sized block of data from the encrypted
     * data into our temporary memory buffer in reverse order */
    for(i = length - 1; i >= 0; i--) 
    {
        B[i] = *eptr;
        eptr++;
    }

    /* so it took me a while to wrap my head around this because I couldn't
     * figure out how the exponent was used in the process.  RSA is 
     * a ^ b (mod c) and I couldn't figure out how that was being done until
     * I realized that the public exponent for lynx decryption is just 3.  That
     * means that to decrypt each block, we only have to multiply each
     * block by itself twice to raise it to the 3rd power:
     * n^3 == n * n * n
     */

    /* TODO: convert this to a loop that calls lynx_mont public_exp number of
     * times so that we can raise the encrypted block of data to the power of
     * public_exp and mod it by public_mod. this will make this flexible
     * enough to be used to encrypt data as well.
     */

    /* do Montgomery multiplication: A = B^2 */
    lynx_mont(A, B, B, public_mod, length);

    /* copy the result into the temp buffer: TMP = B^2 */
    memcpy(TMP, A, length);

    /* do Montgomery multiplication again: A = B^3 */
    lynx_mont(A, B, TMP, public_mod, length);

    /* So I'm not sure if this is part of the Montgomery multiplication 
     * algorithm since I don't fully understand how that works.  This may be
     * just another obfuscation step done during the encryption process. 
     * The output of the decryption process has to be accumulated and masked
     * to get the original bytes.  If I had to place a bet, I would bet that
     * this is not part of Montgomery multiplication and is just an obfuscation
     * preprocessing step done on the plaintext data before it gets encrypted.
     */
    for(i = length - 1; i > 0; i--)
    {
        accumulator += A[i];
        accumulator &= 0xFF;
        (*rptr) = (unsigned char)(accumulator);
        rptr++;
    }
    print_data(result, length);
    
    /* free the temporary buffer memory */
    free(A);
    free(B);
    free(TMP);

    return accumulator;
}


/* this function decrypts a single frame of encrypted data. a frame consists of
 * a single byte block count followed by the count number of blocks of
 * encrypted data.
 */
int decrypt_frame(unsigned char * result, 
                  const unsigned char * encrypted,
                  const unsigned char * public_exp,
                  const unsigned char * public_mod,
                  const int length)
{
    int i, j;
    int blocks;
    int accumulator;
    unsigned char* rptr = result;
    const unsigned char* eptr = encrypted;

    /* reset the accumulator for the modulus step */
    accumulator = 0;

    /* calculate how many encrypted blocks there are */
    blocks = 256 - *eptr;

    /* move our index to the beginning of the next block */
    eptr++;

    for(i = 0; i < blocks; i++)
    {
        /* decrypt a single block of encrypted data */
        accumulator = decrypt_block(accumulator, rptr, eptr, public_exp, public_mod, length);

        /* move result pointer ahead */
        rptr += (length - 1);

        /* move read pointer ahead */
        eptr += length;
    }

    /* return the number of blocks decrypted */
    return blocks;
}

/* this is a completely refactored version of what happens in the Lynx at boot
 * time.  the original code was a very rough reverse of the Lynx ROM code, this
 * is much easier to understand.
 */
void lynx_decrypt(unsigned char * result,
                  const unsigned char * encrypted,
                  const int length)
{
    int blocks = 0;
    int read_index = 0;

    /* decrypt the first frame of encrypted data */
    blocks = decrypt_frame(&result[0],
                           &encrypted[read_index], 
                           /* lynx_public_exp */ 0,
                           lynx_public_mod,
                           length);

#if 0
    /* adjust the read index */
    read_index = 1 + (blocks * length);

    /* decrypte the second frame of encrypted data */
    blocks = decrypt_frame(&result[256],  
                           &encrypted[read_index], 
                           /* lynx_public_exp */ 0,
                           lynx_public_mod,
                           length);
#endif
}

int main(int argc, char *argv[])
{
    /* create a memory buffer to receive the results */
    unsigned char result[FULL_LOADER_LENGTH];

    /* clear out the result buffer */
    memset(result, 0, FULL_LOADER_LENGTH);

    /* decrypt harry's encrypted loader */
    /* lynx_decrypt(result, HarrysEncryptedLoader, CHUNK_LENGTH); */
    lynx_decrypt(result, wookies_micro_loader_encrypted_bin, CHUNK_LENGTH);
    
    /* compare the results against the full plaintext version */
    if(memcmp(result, wookies_micro_loader_plaintext_bin, 50) == 0)
    	printf("LynxDecrypt works\n");
    else 
	    printf("LynxDecrypt fails\n");

    return 0;
}

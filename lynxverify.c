#include <stdio.h>
#include <string.h>
#include "loaders.h"

/*
  Curt Vendell has posted the encryption sources to AtariAge.
  The encryption sources work by indexing everything with the
  least significant byte first.

  In the real Atari Lynx hardware the byte order is LITTLE_ENDIAN.
  If you run this on Intel or AMD CPU then you also have LITTLE_ENDIAN.
  But the original encryption was run on Amiga that has a BIG_ENDIAN CPU.

  This means that all the keys are presented in BIG_ENDIAN format.
*/

#define chunkLength 51
int ptr, c,
    num2, num7,
    ptr5, Cptr, Actr, Xctr, carry, err, ptrEncrypted;
unsigned char buffer[600];
unsigned char result[600];
static unsigned char A[chunkLength];
static unsigned char B[chunkLength];
static unsigned char InputData[chunkLength];
static unsigned char C[chunkLength];
static unsigned char PrivateKey[chunkLength];
static unsigned char E[chunkLength];
static unsigned char F[chunkLength];

#define BIT(C, i, m) ((C)[(i)/8] & (1 << ((i) & 7)))

#define min(x,y) ((x < y) ? x : y)
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

void WriteOperand(FILE * fp, unsigned char *A, int m)
{
    int i;
    unsigned char byte;

    for (i = 0; i < m; i++) {
	byte = A[i];
	fprintf(fp, "%02x", byte);
    }
    fprintf(fp, "\n");
}

/* A = 0 */
static void Clear(unsigned char *A, int m)
{
    int i;

    for (i = 0; i < m; i++)
	A[i] = 0;
}

/* A = 1 */
static void One(unsigned char *A, int m)
{
    Clear(A, m);
    A[0] = 1;
}

/* A = B */
static void Copy(unsigned char *A, unsigned char *B, int m)
{
    int i;

    for (i = 0; i < m; i++)
	A[i] = B[i];
}

/* B = 2*B */
static void Double(unsigned char *B, int m)
{
    int i, x;

    x = 0;
    for (i = 0; i < m; i++) {
	x += 2 * B[i];
	B[i] = (unsigned char) (x & 0xFF);
	x >>= 8;
    }
    /* shouldn't carry */
}

/* B = (B-N) if B >= N */
static int Adjust(unsigned char *B, unsigned char *PublicKey, int m)
{
    int i, x;
    unsigned char T[chunkLength];

    x = 0;
    for (i = 0; i < m; i++) {
	x += B[i] - PublicKey[i];
	T[i] = (unsigned char) (x & 0xFF);
	x >>= 8;
    }

    if (x >= 0) {
	Copy(B, T, m);
        return 1;
    }
    return 0;
}

/* v = -1/PublicKey mod 256 */
static void MontCoeff(unsigned char *v, unsigned char *PublicKey, int m)
{
    int i;
    int lsb = 0;

    *v = 0;
    for (i = 0; i < 8; i++)
	if (!((PublicKey[lsb] * (*v) & (1 << i))))
	    *v += (1 << i);
}

/* A = B*(256**m) mod PublicKey */
static void Mont(unsigned char *A, unsigned char *B, unsigned char *PublicKey,
		 int m)
{
    int i;

    Copy(A, B, m);

    for (i = 0; i < 8 * m; i++) {
	Double(A, m);
	Adjust(A, PublicKey, m);
    }
}

/* A = B*C/(256**m) mod PublicKey where v*PublicKey = -1 mod 256 */
static void MontMult(unsigned char *A, unsigned char *B, unsigned char *C,
		     unsigned char *PublicKey, unsigned char v, int m)
{
    int i, j;
    unsigned char ei, T[2 * chunkLength];
    unsigned int x;

    Clear(T, 2 * m);

    for (i = 0; i < m; i++) {
	x = 0;
	for (j = 0; j < m; j++) {
	    x += (unsigned int) T[i + j] +
		(unsigned int) B[i] * (unsigned int) C[j];
	    T[i + j] = (unsigned char) (x & 0xFF);
	    x >>= 8;
	}
	T[i + m] = (unsigned char) (x & 0xFF);
    }

    for (i = 0; i < m; i++) {
	x = 0;
	ei = (unsigned char) (((unsigned int) v * (unsigned int) T[i]) &
			      0xFF);
	for (j = 0; j < m; j++) {
	    x += (unsigned int) T[i + j] +
		(unsigned int) ei *(unsigned int) PublicKey[j];
	    T[i + j] = (unsigned char) (x & 0xFF);
	    x >>= 8;
	}
	A[i] = (unsigned char) (x & 0xFF);
    }

    x = 0;
    for (i = 0; i < m; i++) {
	x += (unsigned int) T[i + m] + (unsigned int) A[i];
	A[i] = (unsigned char) (x & 0xFF);
	x >>= 8;
    }
    /* shouldn't carry */
}

/* A = (B**PrivateKey)/(256**((PrivateKey-1)*m)) mod PublicKey, where v*PublicKey = -1 mod 256 */
static void MontExp(unsigned char *A, unsigned char *B, unsigned char *PrivateKey,
		    unsigned char *PublicKey, unsigned char v, int m)
{
    int i;
    unsigned char T[chunkLength];

    One(T, m);
    Mont(T, T, PublicKey, m);

    for (i = 8 * m - 1; i >= 0; i--) {
	MontMult(T, T, T, PublicKey, v, m);
	if (BIT(PrivateKey, i, m))
	    MontMult(T, T, B, PublicKey, v, m);
    }

    Copy(A, T, m);
}

/* A = B/(256**m) mod PublicKey, where v*PublicKey = -1 mod 256 */
static void UnMont(unsigned char *A, unsigned char *B, unsigned char *PublicKey,
		   unsigned char v, int m)
{
    unsigned char T[chunkLength];

    One(T, m);
    MontMult(A, B, T, PublicKey, v, m);

    Adjust(A, PublicKey, m);
}

/* All operands have least significant byte first. */
/* A = B**PrivateKey mod PublicKey */
void ModExp(unsigned char *A, unsigned char *B, unsigned char *PrivateKey,
	    unsigned char *PublicKey, int m)
{
    unsigned char T[chunkLength], v;

    MontCoeff(&v, PublicKey, m);
    Mont(T, B, PublicKey, m);
    MontExp(T, T, PrivateKey, PublicKey, v, m);
    UnMont(A, T, PublicKey, v, m);
}

/*
    The inner working of the Lynx. Code created by Harry Dodgson by analyzing
    the Lynx disassembled code
*/
// This is the known public key from the Lynx ROM
// Please note that this key is actually BIG_ENDIAN
// even if it inside the Lynx that is LITTLE_ENDIAN
static unsigned char LynxPublicKey[chunkLength] = {
    0x35, 0xB5, 0xA3, 0x94, 0x28, 0x06, 0xD8, 0xA2,
    0x26, 0x95, 0xD7, 0x71, 0xB2, 0x3C, 0xFD, 0x56,
    0x1C, 0x4A, 0x19, 0xB6, 0xA3, 0xB0, 0x26, 0x00,
    0x36, 0x5A, 0x30, 0x6E, 0x3C, 0x4D, 0x63, 0x38,
    0x1B, 0xD4, 0x1C, 0x13, 0x64, 0x89, 0x36, 0x4C,
    0xF2, 0xBA, 0x2A, 0x58, 0xF4, 0xFE, 0xE1, 0xFD,
    0xAC, 0x7E, 0x79
};


// B = B + F
void add_it(unsigned char *B, unsigned char *F, int m)
{
    int ct, tmp;
    carry = 0;
    for (ct = 0; ct < m; ct++) {
	tmp = B[ct] + F[ct] + carry;
	if (tmp >= 256)
	    carry = 1;
	else
	    carry = 0;
	B[ct] = (unsigned char) (tmp);
    }
}

/* A = B*(256**m) mod PublicKey */
static void LynxMontWorks(unsigned char *A1, unsigned char *B1, unsigned char *PublicKey,
		 int m)
{
    int Yctr;

    Clear(B, m);
    Yctr = 0;
    do {
	int num8, numA;
	numA = F[Yctr];
	num8 = 255;
	do {
	    Double(B, m);
	    carry = (numA & 0x80) / 0x80;
	    numA = (unsigned char) (numA << 1);
	    if (carry != 0) {
		add_it(B, E, m);
                carry = Adjust(B, PublicKey, m);
		if (carry != 0)
                    Adjust(B, PublicKey, m);
	    } else
                Adjust(B, PublicKey, m);
	    num8 = num8 >> 1;
	} while (num8 != 0);
	Yctr++;
    } while (Yctr < m);
}

/* A = B*(256**m) mod PublicKey */
static void LynxMont(unsigned char *A1, unsigned char *B1, unsigned char *PublicKey,
		 int m)
{
    int Yctr;

    Clear(B, m);
    Yctr = 0;
    do {
	int num8, numA;
	numA = F[Yctr];
	num8 = 255;
	do {
	    Double(B, m);
	    carry = (numA & 0x80) / 0x80;
	    numA = (unsigned char) (numA << 1);
	    if (carry != 0) {
		add_it(B, E, m);
                carry = Adjust(B, PublicKey, m);
		if (carry != 0)
                    Adjust(B, PublicKey, m);
	    } else
                Adjust(B, PublicKey, m);
	    num8 = num8 >> 1;
	} while (num8 != 0);
	Yctr++;
    } while (Yctr < m);
}

void sub5000(int m)
{
    Copy(F, E, m);
    LynxMont(B, E, LynxPublicKey, m);
    Copy(F, B, m);
    LynxMont(B, E, LynxPublicKey, m);
}

void convert_it()
{
    int ct;
    long t1, t2;

    num7 = buffer[Cptr];
    num2 = 0;
    Cptr++;
    do {
	int Yctr;

	for (ct = 0; ct < chunkLength; ct++) {
	    E[ct] = buffer[Cptr];
	    Cptr++;
	}
	if ((E[0] | E[1] | E[2]) == 0) {
	    err = 1;
        fprintf(stderr, "332: first three bytes are 0\n");
	}
	t1 = ((long) (E[0]) << 16) +
	    ((long) (E[1]) << 8) +
	    (long) (E[2]);
	t2 = ((long) (LynxPublicKey[0]) << 16) +
	    ((long) (LynxPublicKey[1]) << 8) + (long) (LynxPublicKey[2]);
	if (t1 > t2) {
	    err = 1;
        fprintf(stderr, "341: t1 > t2\n");
	}
	sub5000(chunkLength);
	if (B[0] != 0x15) {
	    err = 1;
        fprintf(stderr, "346: B[0] != 0x15\n");
	}
	Actr = num2;
        // This is not flipped around yet
    //printf("B:\n");
    //print_data(B, 51);
	Yctr = 0x32;
	do {
	    Actr += B[Yctr];
	    Actr &= 255;
	    result[ptr5] = (unsigned char) (Actr);
	    ptr5++;
	    Yctr--;
	} while (Yctr != 0);
	num2 = Actr;
	num7++;
    } while (num7 != 256);
    if (Actr != 0) {
        err = 1;
        fprintf(stderr, "363: Actr != 0\n");
    }
}

// This is what really happens inside the Atari Lynx at boot time
void LynxDecrypt(unsigned char encrypted_data[])
{
    int i;

    memset(buffer, 0, 600);

    ptrEncrypted = 0xAA;
    c = 52;
    for (i = 0; i < c; i++) {
        buffer[i] = encrypted_data[i];
    }
    ptr5 = 0;
    Cptr = 0;
    convert_it();
}

unsigned char AtariPrivateKey[chunkLength];
unsigned char Result[410];

void ReadLength(FILE * fp, int *m)
{
    fscanf(fp, "%d", m);
}

void ReadOperand(FILE * fp, unsigned char *A, int m)
{
    int i;
    unsigned int byte;

    for (i = m - 1; i >= 0; i--) {
	fscanf(fp, "%02x", &byte);
	A[i] = (unsigned char) byte;
    }
}

void CopyOperand(unsigned char *A, unsigned char *B, int m, char inverted)
{
    int i, j;

    if (inverted) {
        int j;
        j = 0;
        for (i = m - 1; i >= 0; i--) {
	    B[j++] = A[i];
        }
    } else {
        for (i = 0; i < m; i++) {
	    B[i] = A[i];
        }
    }
}

#define bool char
#define false 0
#define true 1

bool Compare(unsigned char *A, unsigned char *B, int m)
{
    int i;
    bool res = true;

    for (i = 0; i < m; i++) {
	if (B[i] != A[i])
	    res = false;
    }
    return res;
}

static unsigned char PublicKey[chunkLength];

/* Computes A = InputData**PrivateKey mod PublicKey.
   (1) Inputs length in bytes of operands.
   (2) Inputs InputData, then PrivateKey, then PublicKey, most significant byte first. Most
       significant bit of most significant byte of PublicKey must be zero.
   (3) Computes A.
   (4) Outputs A, most significant byte first.
 */
int main(int argc, char *argv[])
{
    int m;
    memset(result, 0, 600);

    LynxDecrypt(wookies_micro_loader_encrypted_bin);

    printf("output:\n");
    print_data(result, 50);
    printf("expected:\n");
    print_data(wookies_micro_loader_plaintext_bin, 50);

    if (Compare(result, wookies_micro_loader_plaintext_bin, 50)) {
    	printf("LynxDecrypt works\n");
    } else {
	    printf("LynxDecrypt fails\n");
    }

    return 0;
}

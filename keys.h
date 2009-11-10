/* Atari Lynx Encryption Tool
 * Copyright (C) 2009 David Huseby
 *
 * NOTES:
 *
 * This software is original software written completely by me, but there are
 * pieces of data (e.g. the keys.h and loaders.h files) that I got from the 
 * Atari Age Lynx Programming forum and from people in the Lynx community,
 * namely Karri Kaksonen.  Without their help, this would have never been
 * possible.  I was standing on the shoulders of giants.
 *
 * LICENSE:
 *
 * This software is provided 'as-is', without any express or implied warranty. 
 * In no event will the authors be held liable for any damages arising from the 
 * use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose, 
 * including commercial applications, and to alter it and redistribute it 
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not 
 * claim that you wrote the original software. If you use this software in a 
 * product, an acknowledgment in the product documentation would be appreciated 
 * but is not required.
 * 
 * 2. Altered source versions must be plainly marked as such, and must not be 
 * misrepresented as being the original software.
 * 
 * 3. This notice may not be removed or altered from any source distribution. 
 */

#ifndef _KEYS_H_
#define _KEYS_H_

/* This is the public modulus from the Lynx ROM */
const unsigned char lynx_public_mod[LYNX_RSA_KEY_SIZE] = {
    0x35, 0xB5, 0xA3, 0x94, 0x28, 0x06, 0xD8, 0xA2,
    0x26, 0x95, 0xD7, 0x71, 0xB2, 0x3C, 0xFD, 0x56,
    0x1C, 0x4A, 0x19, 0xB6, 0xA3, 0xB0, 0x26, 0x00,
    0x36, 0x5A, 0x30, 0x6E, 0x3C, 0x4D, 0x63, 0x38,
    0x1B, 0xD4, 0x1C, 0x13, 0x64, 0x89, 0x36, 0x4C,
    0xF2, 0xBA, 0x2A, 0x58, 0xF4, 0xFE, 0xE1, 0xFD,
    0xAC, 0x7E, 0x79
};

/* This is the known public exponent from the Lynx ROM.
 * NOTE: the Lynx ROM doesn't actually do a true RSA modular exponentiation
 * using the above modulus and this exponent.  Instead it takes each block of
 * encrypted data and uses Montgomery multiplication to do a modular
 * multiplication of the data block with itself twice, thus raising it to the
 * third power. */
const unsigned char lynx_public_exp[LYNX_RSA_KEY_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x03
};

/* This is the known private exponent generated by xor'ing the three keyfile 
 * blocks together. */
const unsigned char lynx_private_exp[LYNX_RSA_KEY_SIZE] = {
    0x23, 0xce, 0x6d, 0x0d, 0x70, 0x04, 0x90, 0x6c, 
    0x19, 0xb9, 0x3a, 0x4b, 0xcc, 0x28, 0xa8, 0xe4, 
    0x12, 0xdc, 0x11, 0x24, 0x6d, 0x20, 0x19, 0x55, 
    0x79, 0x87, 0xab, 0x5c, 0xa8, 0x18, 0xa3, 0xd3, 
    0xc8, 0xe3, 0x27, 0x6d, 0x42, 0x70, 0xcb, 0x80, 
    0x21, 0xd6, 0xbd, 0xa4, 0x29, 0x6d, 0x47, 0xb1, 
    0xe5, 0xe2, 0xa3
};

/* NOTE: the following keyfile dumps are no longer needed as they are used to
 * calculate the Lynx private exponent which is listed above.  I keep them here
 * for posterity sake so that we don't lose the knowledge that the old Amiga
 * based encryption system used three flopy disks, each containing the following
 * blocks of data that it xor'd together to get the private key in memory.
 */

/* This is the Atari keyfile.1 */
const unsigned char keyfile_1[LYNX_RSA_KEY_SIZE] = {
    0xea, 0x6c, 0xad, 0xb2, 0xab, 0xb1, 0xd3, 0xee,
    0x85, 0x6f, 0xd3, 0x36, 0xc0, 0xc1, 0x16, 0x1d,
    0x31, 0x44, 0x65, 0x1a, 0x22, 0x81, 0xb5, 0xb8,
    0x26, 0xdd, 0xce, 0x0f, 0x8f, 0xbb, 0x25, 0xc8,
    0x1d, 0x34, 0x03, 0x1f, 0xb4, 0xb9, 0xae, 0xda,
    0xcf, 0xde, 0x75, 0xc1, 0xd2, 0xed, 0x35, 0x4b,
    0xcc, 0x11, 0x58
};

/* This is the Atari keyfile.2 */
const unsigned char keyfile_2[LYNX_RSA_KEY_SIZE] = {
    0x14, 0xd6, 0x30, 0x08, 0x35, 0x57, 0x28, 0xef,
    0x2b, 0xa3, 0x25, 0xb7, 0x11, 0x8c, 0x62, 0x2d,
    0x16, 0x7a, 0x7d, 0xee, 0x57, 0xe7, 0x37, 0x18,
    0xc9, 0x96, 0xe5, 0xa9, 0x63, 0x49, 0x68, 0x15,
    0xf6, 0x6c, 0x12, 0x8c, 0x9e, 0xeb, 0xda, 0xef,
    0xbd, 0x75, 0x3a, 0x9e, 0x7d, 0x02, 0xe6, 0xe9,
    0xfd, 0xd7, 0x97
};

/* This is the Atari keyfile.3 */
const unsigned char keyfile_3[LYNX_RSA_KEY_SIZE] = {
    0xdd, 0x74, 0xf0, 0xb7, 0xee, 0xe2, 0x6b, 0x6d,
    0xb7, 0x75, 0xcc, 0xca, 0x1d, 0x65, 0xdc, 0xd4,
    0x35, 0xe2, 0x09, 0xd0, 0x18, 0x46, 0x9b, 0xf5,
    0x96, 0xcc, 0x80, 0xfa, 0x44, 0xea, 0xee, 0x0e,
    0x23, 0xbb, 0x36, 0xfe, 0x68, 0x22, 0xbf, 0xb5,
    0x53, 0x7d, 0xf2, 0xfb, 0x86, 0x82, 0x94, 0x13,
    0xd4, 0x24, 0x6c
};

#endif /*_KEYS_H_ */

#ifndef MY_AES_CBC_H
#define MY_AES_CBC_H

#include "aes.h"

int my_raw_aes_encrypt_cbc(const BYTE in[],           // Plaintext
		                    size_t in_len,            // Must be a multiple of AES_BLOCK_SIZE
		                    BYTE out[],               // Ciphertext, same length as plaintext
		                    const WORD key[],         // From the key setup
		                    int keysize,              // Bit length of the key, 128, 192, or 256
		                    const BYTE iv[]);         // IV, must be AES_BLOCK_SIZE bytes long


int my_raw_aes_decrypt_cbc(const BYTE in[],           // Ciphertext
		                    size_t in_len,            // Must be a multiple of AES_BLOCK_SIZE
		                    BYTE out[],               // Plaintext, same length as ciphertext
		                    const WORD key[],         // From the key setup
		                    int keysize,              // Bit length of the key, 128, 192, or 256
		                    const BYTE iv[]);         // IV, must be AES_BLOCK_SIZE bytes long

int get_file_size(char const * file_name);
int encrypt_file(char const * src_file_name, char const * dst_file_name, const BYTE key[], int keysize, const BYTE iv[]);
int decrypt_file(char const * src_file_name, char const * dst_file_name, const BYTE key[], int keysize, const BYTE iv[]);



#endif   // MY_AES_CBC_H
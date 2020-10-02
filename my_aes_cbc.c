#include <stdlib.h>
#include <memory.h>
#include "aes.h"
#include "my_aes_cbc.h"
#include "utils.h"
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int my_raw_aes_encrypt_cbc(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[]) {
	// Here, we assume in_len % AES_BLOCK_SIZE is zero. 
	int block_num = in_len / AES_BLOCK_SIZE;
	BYTE blk_cal_in_buf[AES_BLOCK_SIZE];
	BYTE blk_cal_out_buf[AES_BLOCK_SIZE];

	memcpy(blk_cal_in_buf, iv, AES_BLOCK_SIZE);

	for (int i = 0; i < block_num; i++) {
		xor(blk_cal_in_buf, in + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		aes_encrypt(blk_cal_in_buf, blk_cal_out_buf, key, keysize);
		memcpy(out + i * AES_BLOCK_SIZE, blk_cal_out_buf, AES_BLOCK_SIZE);
		memcpy(blk_cal_in_buf, blk_cal_out_buf, AES_BLOCK_SIZE);
	}

	return 0;
}

int my_raw_aes_decrypt_cbc(const BYTE in[], size_t in_len, BYTE out[], const WORD key[], int keysize, const BYTE iv[]) {
	// Here, we assume in_len % AES_BLOCK_SIZE is zero. 
	int block_num = in_len / AES_BLOCK_SIZE;

	for (int i = 0; i < block_num; i++) {
		aes_decrypt(in + i * AES_BLOCK_SIZE, out + i * AES_BLOCK_SIZE, key, keysize);
		if (i == 0) {
			xor(out + i * AES_BLOCK_SIZE, iv, AES_BLOCK_SIZE);
		} else {
			xor(out + i * AES_BLOCK_SIZE, in + (i - 1) * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		}
	}

	return 0;
}

int get_file_size(char const * file_name) {
	struct stat fstat;
	if (stat(file_name, &fstat) < 0) {
		return -1;
	}
	return fstat.st_size;
}

int encrypt_file(char const * src_file_name, char const * dst_file_name, const BYTE key[], int keysize, const BYTE iv[]) {
	// check, padding
	int size = get_file_size(src_file_name);
	if (size < 0) {
		fprintf(stderr, "stat error: %s\n", strerror(errno));
		return -1;
	}
	int size_after_padding = size % AES_BLOCK_SIZE == 0 ? size + AES_BLOCK_SIZE : size - size % AES_BLOCK_SIZE + 2 * AES_BLOCK_SIZE;
	int padding_size = size_after_padding - size;

	// extract the file
	FILE* src_file;
	FILE* dst_file;

	if ((src_file = fopen(src_file_name, "rb")) == NULL) {
		fprintf(stderr, "read error: %s\n", strerror(errno));
		return -1;
	}

	BYTE* in_buffer = malloc(size_after_padding * sizeof(BYTE));
	BYTE* out_buffer = malloc(size_after_padding * sizeof(BYTE));

	int count = 0;
	if ((count = fread(in_buffer, sizeof(BYTE), size, src_file)) < size) {
		free(in_buffer);
		free(out_buffer);
		fprintf(stderr, "read error: %s\n", strerror(errno));
		return -1;
	}
	// use the final four bytes to save the original file size
	*((int*)(in_buffer + size_after_padding - sizeof(int))) = size;

	// encrypt and write
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);
	my_raw_aes_encrypt_cbc(in_buffer, size_after_padding, out_buffer, key_schedule, keysize, iv);

	print_hex(in_buffer, size_after_padding, "before");
	print_hex(out_buffer, size_after_padding, "encrypt");

	if ((dst_file = fopen(dst_file_name, "wb")) == NULL) {
		free(in_buffer);
		free(out_buffer);
		fprintf(stderr, "write error: %s\n", strerror(errno));
		return -1;		
	}

	if ((count = fwrite(out_buffer, sizeof(BYTE), size_after_padding, dst_file)) < size_after_padding) {
		free(in_buffer);
		free(out_buffer);
		fprintf(stderr, "write error: %s\n", strerror(errno));
		return -1;
	}

	fclose(dst_file);

	free(in_buffer);
	free(out_buffer);

	return 0;
}

int decrypt_file(char const * src_file_name, char const * dst_file_name, const BYTE key[], int keysize, const BYTE iv[]) {
	// get size after padding
	int size_after_padding = get_file_size(src_file_name);
	if (size_after_padding < 0) {
		fprintf(stderr, "stat error: %s\n", strerror(errno));
		return -1;
	}
	print_format("size_after_padding:%d\n", size_after_padding);

	// extract the file
	FILE* src_file;
	FILE* dst_file;

	if ((src_file = fopen(src_file_name, "rb")) == NULL) {
		fprintf(stderr, "read error: %s\n", strerror(errno));
		return -1;
	}

	BYTE* in_buffer = malloc(size_after_padding * sizeof(BYTE));
	BYTE* out_buffer = malloc(size_after_padding * sizeof(BYTE));

	int count = 0;
	if ((count = fread(in_buffer, sizeof(BYTE), size_after_padding, src_file)) < size_after_padding) {
		free(in_buffer);
		free(out_buffer);
		fprintf(stderr, "read error: %s\n", strerror(errno));
	}

	// decrypt and write
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, keysize);
	my_raw_aes_decrypt_cbc(in_buffer, size_after_padding, out_buffer, key_schedule, keysize, iv);

	// get the real size
	int size = *((int*)(out_buffer + size_after_padding - sizeof(int)));

	print_format("recover size: %d\n", size);
	print_hex(in_buffer, size_after_padding, "before");
	print_hex(out_buffer, size_after_padding, "recover");


	if ((dst_file = fopen(dst_file_name, "wb")) == NULL) {
		free(in_buffer);
		free(out_buffer);
		fprintf(stderr, "write error: %s\n", strerror(errno));
		return -1;		
	}

	if ((count = fwrite(out_buffer, sizeof(BYTE), size, dst_file)) < size) {
		free(in_buffer);
		free(out_buffer);
		fprintf(stderr, "write error: %s\n", strerror(errno));
		return -1;
	}

	fclose(dst_file);

	free(in_buffer);
	free(out_buffer);

	return 0;
}

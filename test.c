#include <stdio.h>
#include <memory.h>
#include "aes.h"
#include "my_aes_cbc.h"
#include "utils.h"
#include "hmac.h"

#define TEXT_LEN 32
#define KEY_LEN 256
#define PLAINTEXT_NUM 2
#define IV_NUM 2
#define KEY_NUM 2

#define HMAC_TEST_NUM 2

// TODO: duplicate
BYTE plaintext[PLAINTEXT_NUM][TEXT_LEN] = {
	{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51},
	{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
};

BYTE iv[IV_NUM][AES_BLOCK_SIZE] = {
	{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
	{0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00}
};

// TODO: duplicate
BYTE key[KEY_NUM][TEXT_LEN] = {
	{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4},
	{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
};

int my_raw_aes_cbc_test() {
	WORD key_schedule[60];
	BYTE correct_enc_buf[128];
	BYTE my_enc_buf[128];
	BYTE correct_dec_buf[128];
	BYTE my_dec_buf[128];

	int pass = 1;
	
	for (int key_i = 0; key_i < KEY_NUM; key_i++) {
		aes_key_setup(key[key_i], key_schedule, KEY_LEN);
		for (int iv_i = 0; iv_i < IV_NUM; iv_i++) {
			for (int pt_i = 0; pt_i < PLAINTEXT_NUM; pt_i++) {
				aes_encrypt_cbc(plaintext[pt_i], TEXT_LEN, correct_enc_buf, key_schedule, KEY_LEN, iv[iv_i]);
				my_raw_aes_encrypt_cbc(plaintext[pt_i], TEXT_LEN, my_enc_buf, key_schedule, KEY_LEN, iv[iv_i]);
				print_hex(correct_enc_buf, TEXT_LEN, "encrypt correct");
				print_hex(my_enc_buf, TEXT_LEN, "encrypt my");
				pass = pass && !memcmp(correct_enc_buf, my_enc_buf, TEXT_LEN);

				aes_decrypt_cbc(correct_enc_buf, TEXT_LEN, correct_dec_buf, key_schedule, KEY_LEN, iv[iv_i]);
				my_raw_aes_decrypt_cbc(my_enc_buf, TEXT_LEN, my_dec_buf, key_schedule, KEY_LEN, iv[iv_i]);
				print_hex(correct_dec_buf, TEXT_LEN, "decrypt correct");
				print_hex(my_dec_buf, TEXT_LEN, "decrypt my");
				pass = pass && !memcmp(correct_dec_buf, my_dec_buf, TEXT_LEN);
			}
		}
	}

	return pass;
}

// correct hash values are generated from: https://www.devglan.com/online-tools/hmac-sha256-online
int hmac_test() {
	int pass = 1;
	struct test_case {
		BYTE* key;
		BYTE* msg;
		int msg_len;
		BYTE correct_hmac[SHA_OUTPUT_SIZE];
	} test_cases[HMAC_TEST_NUM] = {
		{
			"12341234123412341234123412341234", 
			"abcdefghijklmnopqrstuvwxyz", 
			26,
			{
				0x56,0xd3,0xb6,0x66,0xf8,0x2e,0xf5,0xc1,
				0xaa,0x2a,0xc5,0x25,0x74,0x69,0xe7,0xf6,
				0x43,0x8c,0xc3,0x37,0x4a,0x30,0x74,0x29,
				0x24,0x68,0xf5,0x6d,0xb7,0x5e,0x2b,0x68
			}
		},
		{
			"abcdefghijklmnopqrstuvwxyz123456", 
			"The quick brown fox jumps over the lazy dog", 
			43,
			{
				0x5a,0xd1,0x43,0x59,0x83,0xbb,0x36,0x8d,
				0x6a,0x52,0x26,0x7f,0x5e,0x48,0xcc,0x89,
				0x77,0x27,0x21,0xda,0x36,0xb8,0x84,0xd6,
				0x3c,0x3f,0x2d,0xf2,0x7f,0xcf,0x66,0x18
			}
		}
	};

	BYTE buf[SHA_OUTPUT_SIZE];

	for (int i = 0; i < HMAC_TEST_NUM; i++) {
		struct test_case tc = test_cases[i];
		hmac(tc.key, tc.msg, tc.msg_len, buf);
		print_hex(tc.correct_hmac, SHA_OUTPUT_SIZE, "correct hmac");
		print_hex(buf, SHA_OUTPUT_SIZE, "my hmac");
		pass = pass && !memcmp(buf, tc.correct_hmac, TEXT_LEN);
	}

	return pass;
}

int main(int argc, char *argv[]) {
	//printf("My RAW AES CBC mode tests: %s\n", my_raw_aes_cbc_test() ? "SUCCEEDED" : "FAILED");
	//printf("%d\n", get_file_size("./testfiles/a.txt"));
	//printf("%d\n", encrypt_file("./testfiles/a.txt", "./encrypt.txt", key[0], KEY_LEN, iv[0]));
	//printf("%d\n", decrypt_file("./encrypt.txt", "./recover.txt", key[0], KEY_LEN, iv[0]));
	printf("My hmac tests: %s\n", hmac_test() ? "SUCCEEDED" : "FAILED");
	return 0;
}
#include "my_aes_cbc.h"
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include "dirent.h"
#include "sha256.h"
#include "hmac.h"
#include <fcntl.h>
#include "utils.h"

#define INIT_CMD 0
#define LIST_CMD 1
#define ADD_CMD 2
#define EXTRACT_CMD 3
#define DELETE_CMD 4

#define COLLECT_SIZE_PHASE 1
#define COLLECT_CONTENT_PHASE 2
#define LIST_NAME 3

#define KEY_LEN 256

struct ARCHIVE_INFO {
	int size;
	int offset;
	BYTE* content;
	BYTE stored_hmac[SHA_OUTPUT_SIZE];
	BYTE new_hmac[SHA_OUTPUT_SIZE];
};

int archive_path_len = 0;

void clear_path_buf(char path_buf[], const int i) {
	memset(path_buf + i, '\0', 4097 - i);
}

int is_valid_cmd(char const * cmd) {
	if (strcmp(cmd, "init") == 0) {
		return INIT_CMD;
	}
	if (strcmp(cmd, "list") == 0) {
		return LIST_CMD;
	}
	if (strcmp(cmd, "add") == 0) {
		return ADD_CMD;
	}
	if (strcmp(cmd, "extract") == 0) {
		return EXTRACT_CMD;
	}
	if (strcmp(cmd, "delete") == 0) {
		return DELETE_CMD;
	}
	return -1;	
}

char* get_real_file_name(char const * raw_name) {
	int raw_name_len = strlen(raw_name);
	int i = raw_name_len - 1;
	for (; i >= 0; i--) {
		if (raw_name[i] == '/') {
			break;
		}
	}
	char* name = malloc(300 * sizeof(char));
	memset(name, '\0', 300);
	strcpy(name, raw_name + i + 1);
	return name;
}

int deal_with_pw(int argc, char const *argv[], BYTE verification_key[], BYTE crypt_key[]) {
	char const * password;
	int arch_name_i;
	if (strcmp(argv[2], "-p") == 0) {
		if (argc < 5) {
			printf("Please input enough arguments.\n");
			return -1;
		}
		arch_name_i = 4;
		password = argv[3];
	} else {
		arch_name_i = 2;
		password = getpass("Input a password:");
	}
	print_format("pw:[%s]\n", password);
	print_format("strlen(password):%ld\n", strlen(password));

	SHA256_CTX ctx;

	sha256_init(&ctx);
	for (int idx = 0; idx < 10000; idx++)
	   sha256_update(&ctx, (BYTE*)password, strlen(password));
	sha256_final(&ctx, verification_key);
	print_hex(verification_key, SHA_OUTPUT_SIZE, "verification_key (pw hash 10000 times):");

	sha256_init(&ctx);
	for (int idx = 0; idx < 20000; idx++)
	   sha256_update(&ctx, (BYTE*)password, strlen(password));
	sha256_final(&ctx, crypt_key);
	print_hex(crypt_key, SHA_OUTPUT_SIZE, "crypt_key (pw hash 20000 times):");
	return arch_name_i;
}

int is_dot_entry(struct dirent* entry) {
	return strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0;
}

int is_hmac_entry(struct dirent* entry) {
	return strcmp(entry->d_name, "hmac") == 0;
}

int is_iv_entry(struct dirent* entry) {
	return strlen(entry->d_name) > 3 && entry->d_name[0] == 'i' && entry->d_name[1] == 'v' && entry->d_name[2] == '_';
}

int is_init_entry(struct dirent* entry) {
	return strcmp(entry->d_name, "init.txt") == 0;
}

void get_random_iv(BYTE iv[], const int iv_len) {
	int random_fd = open("/dev/urandom", O_RDONLY);
	read(random_fd, iv, iv_len);
	close(random_fd);
}

void init_archive_info(struct ARCHIVE_INFO* info) {
	info->size = 0;
	info->offset = 0;
	info->content = NULL;
	for (int i = 0; i < SHA_OUTPUT_SIZE; i++) {
		info->stored_hmac[i] = 0x00;
		info->new_hmac[i] = 0x00;
	}
}

int collect(char archive_path[], struct ARCHIVE_INFO* info, int mode) {
	if (mode == COLLECT_CONTENT_PHASE) {
		info->content = malloc(info->size * sizeof(BYTE));
		if (info->content == NULL) {
			fprintf(stderr, "malloc error: %s\n", strerror(errno));
			return -1;
		}
	}

	struct stat fstat;

	DIR* dir;
	struct dirent* entry;
	dir = opendir(archive_path);
	if (dir == NULL) {
		fprintf(stderr, "opendir error: %s\n", strerror(errno));
		return -1;
	}
	while ((entry = readdir(dir)) != NULL) {
		if (is_dot_entry(entry)) {
			continue;
		}
		if (mode == LIST_NAME) {
			if (!is_hmac_entry(entry) && !is_iv_entry(entry) && !is_init_entry(entry)) {
				printf("%s\n", entry->d_name + 1);
			}
			continue;
		}
		clear_path_buf(archive_path, archive_path_len);
		strcat(archive_path, entry->d_name);
		if (stat(archive_path, &fstat) < 0) {
			clear_path_buf(archive_path, archive_path_len);
			fprintf(stderr, "stat error: %s\n", strerror(errno));
			closedir(dir);
			return -1;	
		}
		print_format("%s size:%ld\n", archive_path, fstat.st_size);
		if (mode == COLLECT_SIZE_PHASE) {
			if (!is_hmac_entry(entry)) {
				info->size += (fstat.st_size + sizeof(off_t) + strlen(entry->d_name) + sizeof(size_t));
				print_format("archive size:%d\n", info->size);
			}
		} else if (mode == COLLECT_CONTENT_PHASE) {
			// extract the file
			FILE* src_file;
			if ((src_file = fopen(archive_path, "rb")) == NULL) {
				clear_path_buf(archive_path, archive_path_len);
				fprintf(stderr, "read error: %s\n", strerror(errno));
				return -1;
			}
			if (is_hmac_entry(entry)) {
				if (fread(info->stored_hmac, sizeof(BYTE), SHA_OUTPUT_SIZE, src_file) < SHA_OUTPUT_SIZE) {
					clear_path_buf(archive_path, archive_path_len);
					fprintf(stderr, "read error: %s\n", strerror(errno));
					return -1;
				}
			} else {
				if (fread(info->content + info->offset, sizeof(BYTE), fstat.st_size, src_file) < fstat.st_size) {
					clear_path_buf(archive_path, archive_path_len);
					fprintf(stderr, "read error: %s\n", strerror(errno));
					return -1;
				}
				info->offset += fstat.st_size;
				memcpy(info->content + info->offset, &fstat.st_size, sizeof(off_t));
				info->offset += sizeof(off_t);
				size_t tmp_len = strlen(entry->d_name);
				memcpy(info->content + info->offset, entry->d_name, tmp_len);
				info->offset += tmp_len;
				memcpy(info->content + info->offset, &tmp_len, sizeof(size_t));
				info->offset += sizeof(size_t);
			}
			fclose(src_file);
			// print_hex(info->content, info->offset, "now");
		}
		clear_path_buf(archive_path, archive_path_len);
	}
	closedir(dir);

	return 0;
}

int get_hmac_of_archive(char archive_path[], struct ARCHIVE_INFO* info, const BYTE verification_key[]) {
	if (collect(archive_path, info, COLLECT_SIZE_PHASE) < 0) {
		return -1;
	}
	if (collect(archive_path, info, COLLECT_CONTENT_PHASE) < 0) {
		return -1;
	}
	hmac(verification_key, info->content, info->size, info->new_hmac);
	return 0;
}

int recalculate_archive(char path_buf[], const BYTE verification_key[]) {
	struct ARCHIVE_INFO info;
	init_archive_info(&info);
	if (get_hmac_of_archive(path_buf, &info, verification_key) < 0) {
		return -1;
	}
	FILE* hmac_file;
	strcat(path_buf, "hmac");
	if ((hmac_file = fopen(path_buf, "wb")) == NULL) {
		clear_path_buf(path_buf, archive_path_len);
		fprintf(stderr, "write error: %s\n", strerror(errno));
		return -1;		
	}
	if (fwrite(info.new_hmac, sizeof(BYTE), SHA_OUTPUT_SIZE, hmac_file) < SHA_OUTPUT_SIZE) {
		clear_path_buf(path_buf, archive_path_len);
		fprintf(stderr, "write error: %s\n", strerror(errno));
		return -1;
	}
	fclose(hmac_file);
	clear_path_buf(path_buf, archive_path_len);
	return 0;
}

int verify_archive(char path_buf[], const BYTE verification_key[]) {
	struct ARCHIVE_INFO info;
	init_archive_info(&info);
	if (get_hmac_of_archive(path_buf, &info, verification_key) < 0) {
		return -1;
	}
	for (int i = 0; i < SHA_OUTPUT_SIZE; i++) {
		if (info.stored_hmac[i] != info.new_hmac[i]) {
			return 1;
		}
	}
	clear_path_buf(path_buf, archive_path_len);
	return 0;
}

int main(int argc, char const *argv[]) {
	if (argc < 3) {
		printf("Please input enough arguments.\n");
		return -1;
	}
	// args >= 3
	int cmd_type = is_valid_cmd(argv[1]);
	if (cmd_type < 0) {
		printf("Command %s is not supported.", argv[1]);
		return -1;
	}

	char root_dir[] = "/tmp/cstore/";

	// if we do not have a cstore base, create one
	struct stat fstat;
	if (stat(root_dir, &fstat) < 0) {
		if (mkdir(root_dir, 0700) < 0) {
			fprintf(stderr, "mkdir error: %s\n", strerror(errno));
			return -1;
		}
	}

	// max length of path is 4097 chars
	char path_buf[4097];
	// check if we have this archive now
	clear_path_buf(path_buf, 0);
	strcat(path_buf, root_dir);

	int arch_name_i;
	BYTE verification_key[SHA_OUTPUT_SIZE];
	BYTE crypt_key[SHA_OUTPUT_SIZE];

	// init
	if (cmd_type == INIT_CMD) {
		if ((arch_name_i = deal_with_pw(argc, argv, verification_key, crypt_key)) < 0) {
			return -1;
		}
		strcat(path_buf, argv[arch_name_i]);
		strcat(path_buf, "/");
		if (stat(path_buf, &fstat) >= 0) {
			printf("Archive %s already exists.\n", argv[arch_name_i]);
			return -1;
		}
		if (mkdir(path_buf, 0700) < 0) {
			fprintf(stderr, "mkdir error: %s\n", strerror(errno));
			return -1;
		}

		archive_path_len = strlen(path_buf);

		FILE* init_file;
		strcat(path_buf, "init.txt");
		if ((init_file = fopen(path_buf, "w")) == NULL) {
			fprintf(stderr, "write error: %s\n", strerror(errno));
			return -1;		
		}
		if (fwrite("init\n", sizeof(char), 5, init_file) < 5) {
			fprintf(stderr, "write error: %s\n", strerror(errno));
			return -1;
		}
		fclose(init_file);
		clear_path_buf(path_buf, archive_path_len);
		recalculate_archive(path_buf, verification_key);
		printf("Archive %s is successfully initialized.\n", argv[arch_name_i]);
		return 0;
	}

	// list
	if (cmd_type == LIST_CMD) {
		// args >= 3
		strcat(path_buf, argv[2]);
		strcat(path_buf, "/");
		if (stat(path_buf, &fstat) < 0) {
			printf("Archive %s does not exist or was deleted by someone.\n", argv[2]);
			return -1;
		}

		archive_path_len = strlen(path_buf);

		printf("Files in the archive %s:\n", argv[2]);
		if (collect(path_buf, NULL, LIST_NAME) < 0) {
			return -1;
		}
		return 0;
	}

	// deal with the password
	if ((arch_name_i = deal_with_pw(argc, argv, verification_key, crypt_key)) < 0) {
		return -1;
	}

	strcat(path_buf, argv[arch_name_i]);
	strcat(path_buf, "/");
	if (stat(path_buf, &fstat) < 0) {
		printf("%s does not exists, which means archive %s does not exist or was deleted by someone.\n", path_buf, argv[arch_name_i]);
		return -1;
	}

	archive_path_len = strlen(path_buf);

	// validate the password or integrity
	int verify_status = verify_archive(path_buf, verification_key);
	if (verify_status == -1) {
		return -1;
	}
	if (verify_status == 1) {
		printf("Your password is not correct or the integrity of archive %s is broken by someone.\n", argv[arch_name_i]);
		return -1;
	}

	printf("Password verification passed.\n");

	
	if (strcmp(argv[1], "add") == 0) {
		BYTE iv[AES_BLOCK_SIZE];
		for (int i = arch_name_i + 1; i < argc; i++) {
			clear_path_buf(path_buf, archive_path_len);
			char* real_file_name = get_real_file_name(argv[i]);
			strcat(path_buf, "_");
			strcat(path_buf, real_file_name);

			if (stat(path_buf, &fstat) >= 0) {
				printf("File %s already exists in archive %s. Skip it.\n", real_file_name, argv[arch_name_i]);
				clear_path_buf(path_buf, archive_path_len);
				free(real_file_name);
				continue;
			}

			get_random_iv(iv, AES_BLOCK_SIZE);

			if (encrypt_file(argv[i], path_buf, crypt_key, KEY_LEN, iv) < 0) {
				free(real_file_name);
				return -1;
			}

			FILE* iv_file;
			clear_path_buf(path_buf, archive_path_len);
			strcat(path_buf, "iv_");
			strcat(path_buf, real_file_name);
			if ((iv_file = fopen(path_buf, "wb")) == NULL) {
				free(real_file_name);
				fprintf(stderr, "write error: %s\n", strerror(errno));
				return -1;		
			}
			if (fwrite(iv, sizeof(BYTE), AES_BLOCK_SIZE, iv_file) < AES_BLOCK_SIZE) {
				free(real_file_name);
				fprintf(stderr, "write error: %s\n", strerror(errno));
				return -1;
			}
			fclose(iv_file);

			printf("File %s is successfully added to archive %s.\n", argv[i], argv[arch_name_i]);
			clear_path_buf(path_buf, archive_path_len);
			free(real_file_name);
		}
		recalculate_archive(path_buf, verification_key);
	} else if (strcmp(argv[1], "extract") == 0) {
		BYTE iv[AES_BLOCK_SIZE];
		for (int i = arch_name_i + 1; i < argc; i++) {
			clear_path_buf(path_buf, archive_path_len);
			strcat(path_buf, "_");
			strcat(path_buf, argv[i]);
			if (stat(path_buf, &fstat) < 0) {
				printf("File %s does not exist in archive %s. Skip it.\n", argv[i], argv[arch_name_i]);
				continue;
			}

			clear_path_buf(path_buf, archive_path_len);
			strcat(path_buf, "iv_");
			strcat(path_buf, argv[i]);
			FILE* iv_file;
			if ((iv_file = fopen(path_buf, "rb")) == NULL) {
				fprintf(stderr, "read error: %s\n", strerror(errno));
				return -1;		
			}
			if (fread(iv, sizeof(BYTE), AES_BLOCK_SIZE, iv_file) < AES_BLOCK_SIZE) {
				fprintf(stderr, "read error: %s\n", strerror(errno));
				return -1;
			}

			clear_path_buf(path_buf, archive_path_len);
			strcat(path_buf, "_");
			strcat(path_buf, argv[i]);
			if (decrypt_file(path_buf, argv[i], crypt_key, KEY_LEN, iv) < 0) {
				return -1;
			}

			printf("File %s is successfully extracted from archive %s to the current working directory.\n", argv[i], argv[arch_name_i]);

			clear_path_buf(path_buf, archive_path_len);
		}
	} else if (strcmp(argv[1], "delete") == 0) {
		for (int i = arch_name_i + 1; i < argc; i++) {
			clear_path_buf(path_buf, archive_path_len);
			strcat(path_buf, "_");
			strcat(path_buf, argv[i]);

			if (stat(path_buf, &fstat) < 0) {
				printf("File %s does not exist in archive %s. Skip it.\n", argv[i], argv[arch_name_i]);
				clear_path_buf(path_buf, archive_path_len);
				continue;
			}

			if (remove(path_buf) < 0) {
				return -1;
			}

			clear_path_buf(path_buf, archive_path_len);
			strcat(path_buf, "iv_");
			strcat(path_buf, argv[i]);

			if (remove(path_buf) < 0) {
				return -1;
			}

			printf("File %s is successfully deleted from archive %s.\n", argv[i], argv[arch_name_i]);
			clear_path_buf(path_buf, archive_path_len);
		}
		recalculate_archive(path_buf, verification_key);
	}
	
	return 0;
}
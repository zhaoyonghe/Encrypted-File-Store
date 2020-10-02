#ifndef HMAC_H
#define HMAC_H

#include "sha256.h"

#define BLOCK_SIZE 64
#define SHA_OUTPUT_SIZE 32

void hmac(const BYTE key[], const BYTE message[], const int msg_len, BYTE buf[]);

#endif   // HMAC_H
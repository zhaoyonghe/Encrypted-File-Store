#ifndef UTILS_H
#define UTILS_H

#include "aes.h"

#define DEBUG_MODE 1

void print_format(const char* format, ...);
void print_hex(BYTE str[], int len, char* title);
void xor(BYTE a[], const BYTE b[], int len);

#endif   // UTILS_H
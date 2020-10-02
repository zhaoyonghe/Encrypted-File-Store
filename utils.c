#include "utils.h"
#include <stdio.h>
#include <stdarg.h>

void print_format(const char* format, ...) {
	if (DEBUG_MODE == 0) {
		return;
	}

	va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void print_hex(BYTE str[], int len, char* title) {
	if (DEBUG_MODE == 0) {
		return;
	}

	int idx;

	printf("%s:\n", title);
	for(idx = 0; idx < len; idx++)
		printf("%02x", str[idx]);
	printf("\n");
}

// the result of a xor b is saved to a
void xor(BYTE a[], const BYTE b[], int len) {
	for (int i = 0; i < len; i++) {
		a[i] = a[i] ^ b[i];
	}
}
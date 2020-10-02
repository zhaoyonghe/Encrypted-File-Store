default: main test

main: utils.o sha256.o hmac.o aes.o my_aes_cbc.o
	gcc main.c utils.o sha256.o hmac.o aes.o my_aes_cbc.o -o cstore

test: clean utils.o aes.o my_aes_cbc.o sha256.o hmac.o
	gcc test.c utils.o aes.o my_aes_cbc.o sha256.o hmac.o -o test

my_aes_cbc.o:
	gcc -c my_aes_cbc.c

aes.o:
	gcc -c aes.c

hmac.o:
	gcc -c hmac.c

sha256.o:
	gcc -c sha256.c

utils.o:
	gcc -c utils.c

.PHONY: clean
clean:
	rm *.o *.txt test cstore || true

.PHONY: all
all: clean default
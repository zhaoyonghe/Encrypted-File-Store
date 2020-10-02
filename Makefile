default: clean all

all: utils.o sha256.o hmac.o aes.o my_aes_cbc.o
	gcc main.c utils.o sha256.o hmac.o aes.o my_aes_cbc.o -o cstore
	gcc test.c utils.o sha256.o hmac.o aes.o my_aes_cbc.o -o cstore_test

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

clean:
	rm *.o *.txt test cstore || true

test:
	./cstore_test

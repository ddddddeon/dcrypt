NAME=dcrypt
LIBS=-lcrypto
TEST_LIBS=-lcrypto -L./bin -ldcrypt
CFLAGS=-g -Wall -DDCRYPT_VERBOSE -I./src#-DDCRYPT_MIN_RSA_BITS=1024 -DDCRYPT_MAX_RSA_BITS=65535

CC=clang
LIB_DIR=/usr/lib/
LIBNAME=lib$(NAME).so
LIB_OUTFILE=bin/$(LIBNAME)
INFILES=$(wildcard src/*.c)
TEST_INFILES=$(wildcard test/*.c)
TEST_OUTFILE=bin/test

.PHONY: $(NAME)

$(NAME): library
	set -e; \
	$(CC) -shared -o $(LIB_OUTFILE) $(wildcard bin/*.o); \
	$(CC) -o $(TEST_OUTFILE) $(TEST_INFILES) $(LIB_OUTFILE) $(CFLAGS) -fuse-ld=lld $(LIBS); \
	$(CC) -o bin/example ./example.c $(LIB_OUTFILE) $(CFLAGS) -fuse-ld=lld $(LIBS);

library:
	set -e; \
	if [ ! -d bin ]; then mkdir bin; fi; \
	for FILE in $(INFILES); do \
		$(CC) $(CFLAGS) -c -fPIC $$FILE -o bin/$$(basename $${FILE%%.*}).o;\
	done; \

clean:	findBin
	@rm -rf bin;

findBin:
	@[ -d bin ];

install:
	@mv $(LIB_OUTFILE) $(LIB_DIR)$(LIBNAME); \
	echo "[OK] installed to $(LIB_DIR)$(NAME)";

check:
	@valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes ./bin/test;

trace:
	@strace ./bin/test

all: $(NAME) findBin install

rebuild: clean $(NAME) install

flush:
	rm ./id_rsa*;
NAME=dcrypt
CC=clang
LD=lld
LIBS=-lcrypto
INCLUDES=-I./src
TEST_LIBS=-lcrypto -L./bin -ldcrypt
USE_LINKER=-fuse-ld=$(LD)
CFLAGS=-g -Wall -DDCRYPT_VERBOSE $(INCLUDES) #-DDCRYPT_MIN_RSA_BITS=1024 -DDCRYPT_MAX_RSA_BITS=65535
LIB_DIR=/usr/lib/
LIBNAME=lib$(NAME).so
LIB_OUTFILE=bin/$(LIBNAME)
INFILES=$(wildcard src/*.c)
HEADER_INFILES=$(wildcard src/*.h)
HEADER_OUTPATH=/usr/include/
TEST_INFILES=$(wildcard test/*.c)
TEST_OUTFILE=bin/test

.PHONY: $(NAME)

$(NAME): library
	set -e; \
	$(CC) -shared -o $(LIB_OUTFILE) $(wildcard bin/*.o); \
	$(CC) -o $(TEST_OUTFILE) $(TEST_INFILES) $(LIB_OUTFILE) $(CFLAGS) $(USE_LINKER) $(LIBS); \
	$(CC) -o bin/example ./example.c $(LIB_OUTFILE) $(CFLAGS) $(USE_LINKER) $(LIBS);

library:
	set -e; \
	if [ ! -d bin ]; then mkdir bin; fi; \
	for FILE in $(INFILES); do \
		$(CC) $(CFLAGS)-c -fPIC $$FILE -o bin/$$(basename $${FILE%%.*}).o;\
	done; \

clean:	findBin
	@rm -rf bin;

findBin:
	@[ -d bin ];

install:
	@cp $(LIB_OUTFILE) $(LIB_DIR)$(LIBNAME); \
	for FILE in $(HEADER_INFILES); do \
		cp $$FILE $(HEADER_OUTPATH)$$(basename $${FILE%%.*}.h); \
	done;

check:
	@valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes ./bin/test;

trace:
	@strace ./bin/test

all: $(NAME) findBin install

rebuild: clean $(NAME) install

flush:
	rm ./id_rsa*;
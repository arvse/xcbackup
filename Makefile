# XCBackup Makefile
CONFIG=-D_GNU_SOURCE -DENABLE_ENCRYPTION -DENABLE_STDIN_PASSWORD
INCLUDES=-I include $(CONFIG)
INDENT_FLAGS=-br -ce -i4 -bl -bli0 -bls -c4 -cdw -ci4 -cs -nbfda -l100 -lp -prs -nlp -nut -nbfde -npsl -nss
LIBS=-lmbedcrypto

OBJS = \
	bin/main.o \
	bin/unpack.o \
	bin/pack.o \
	bin/stream.o \
	bin/files.o \
	bin/util.o \
	bin/file.o \
	bin/buffer.o \
	bin/aes.o

all: host

internal: prepare
	@echo "  CC    src/aes.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/aes.c -o bin/aes.o
	@echo "  CC    src/file.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/file.c -o bin/file.o
	@echo "  CC    src/buffer.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/buffer.c -o bin/buffer.o
	@echo "  CC    src/main.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/main.c -o bin/main.o
	@echo "  CC    src/unpack.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/unpack.c -o bin/unpack.o
	@echo "  CC    src/pack.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/pack.c -o bin/pack.o
	@echo "  CC    src/stream.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/stream.c -o bin/stream.o
	@echo "  CC    src/files.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/files.c -o bin/files.o
	@echo "  CC    src/util.c"
	@$(CC) $(CFLAGS) $(INCLUDES) src/util.c -o bin/util.o
	@echo "  LD    bin/xcbackup"
	@$(LD) -o bin/xcbackup $(OBJS) $(LDFLAGS) $(LIBS)

prepare:
	@mkdir -p bin

host:
	@make internal \
		CC=gcc \
		LD=gcc \
		CFLAGS='-c -Wall -Wextra -O2 -ffunction-sections -fdata-sections -Wstrict-prototypes' \
		LDFLAGS='-s -Wl,--gc-sections -Wl,--relax'

indent:
	@indent $(INDENT_FLAGS) ./*/*.h
	@indent $(INDENT_FLAGS) ./*/*.c
	@rm -rf ./*/*~

clean:
	@rm -rf bin

install:
	@cp -v bin/xcbackup /usr/bin/xcbackup

uninstall:
	@rm -fv /usr/bin/xcbackup

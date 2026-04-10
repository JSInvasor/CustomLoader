CC = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -s -Wall
LDFLAGS = -lgdi32 -lwininet

all: loader.exe ghost_loader.exe xor_encode.exe bin2header.exe

loader.exe: loader.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

ghost_loader.exe: ghost_loader.c
	$(CC) $(CFLAGS) -masm=att -o $@ $<

# Embedded build: compile shellcode into the binary
# Usage: make embedded XOR_KEY=42
embedded: shellcode.h
	$(CC) $(CFLAGS) -DEMBED -o loader.exe loader.c $(LDFLAGS)

shellcode.h: bin2header.exe
	@echo "Run: bin2header.exe payload.bin shellcode.h [xor_key]"

xor_encode.exe: xor_encode.c
	$(CC) $(CFLAGS) -o $@ $<

bin2header.exe: bin2header.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f loader.exe xor_encode.exe bin2header.exe shellcode.h

.PHONY: all clean embedded

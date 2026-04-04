CC = x86_64-w64-mingw32-gcc
CFLAGS = -O2 -s -Wall
LDFLAGS = -lgdi32

all: loader.exe xor_encode.exe

loader.exe: loader.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

xor_encode.exe: xor_encode.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f loader.exe xor_encode.exe

.PHONY: all clean

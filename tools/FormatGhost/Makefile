CC = x86_64-w64-mingw32-gcc
all: format_ghost.dll

format_ghost.dll: format_ghost.c
	$(CC) -shared -O2 -o $@ $< -s

clean:
	rm -f format_ghost.dll

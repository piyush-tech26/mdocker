CC=gcc
CFLAGS=-Wall -Wextra

all: mdocker

mdocker: main.c
	$(CC) $(CFLAGS) main.c -o mdocker

clean:
	rm -f mdocker

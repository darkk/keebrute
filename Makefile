CFLAGS := -O2 -W -Wall -Wextra
LDFLAGS := -pthread -lcrypto
keebrute: keebrute.o
	$(CC) $^ $(LDFLAGS) -o $@

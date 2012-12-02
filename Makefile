CFLAGS := -O2
LDFLAGS := -pthread -lcrypto
keebrute: keebrute.o
	$(CC) $^ $(LDFLAGS) -o $@

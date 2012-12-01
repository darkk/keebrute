CFLAGS := -O2
LDFLAGS := -lcrypto
keebrute: keebrute.o
	$(CC) $^ $(LDFLAGS) -o $@

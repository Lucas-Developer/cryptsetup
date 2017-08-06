TARGET=keyslot_test
LIBNVCRYPT_PATH=/home/user/usr/lib
LIBNVCRYPT_INCLUDE=/home/user/usr/include
CFLAGS=-O0 -g -Wall -D_GNU_SOURCE -I ../../lib/ -I$(LIBNVCRYPT_INCLUDE)
LDLIBS=-ljson-c -luuid -lgcrypt -ldevmapper -lpthread -lssh
LDLIBS_NVCRYPT=-lm -lnvcrypt -lpopt
CC=gcc

TARGET2=keyslot_test_remote_pass
TARGET3=keyslot_test_keyring
TARGET4=keyslot_add_by_key
TARGET5=nvcrypt_token
TARGET6=nvcrypt_token_keyring

SOURCES=keyslot_test.c
OBJECTS=$(SOURCES:.c=.o)
SOURCES2=keyslot_test_remote_pass.c
OBJECTS2=$(SOURCES2:.c=.o)
SOURCES3=keyslot_test_keyring.c
OBJECTS3=$(SOURCES3:.c=.o)
SOURCES4=keyslot_add_by_key.c
OBJECTS4=$(SOURCES4:.c=.o)
SOURCES5=nvcrypt_token.c
OBJECTS5=$(SOURCES5:.c=.o)
SOURCES6=nvcrypt_token_keyring.c
OBJECTS6=$(SOURCES6:.c=.o)

all: $(TARGET) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5) $(TARGET6)

$(TARGET): $(OBJECTS) ../../lib/.libs/libcryptsetup.a
	$(CC) -o $@ $^ $(LDLIBS)

$(TARGET2): $(OBJECTS2) ../../lib/.libs/libcryptsetup.a
	$(CC) -o $@ $^ $(LDLIBS)

$(TARGET3): $(OBJECTS3) ../../lib/.libs/libcryptsetup.a
	$(CC) -o $@ $^ $(LDLIBS)

$(TARGET4): $(OBJECTS4) ../../lib/.libs/libcryptsetup.a
	$(CC) -o $@ $^ $(LDLIBS)

$(TARGET5): $(OBJECTS5) ../../src/cryptsetup-utils_tools.o ../../src/cryptsetup-utils_password.o ../../lib/.libs/libcryptsetup.a
	$(CC) -o $@ $^ $(LDLIBS) $(LDLIBS_NVCRYPT) -L$(LIBNVCRYPT_PATH)

$(TARGET6): $(OBJECTS6) ../../src/cryptsetup-utils_tools.o ../../src/cryptsetup-utils_password.o ../../lib/.libs/libcryptsetup.a
	$(CC) -o $@ $^ $(LDLIBS) $(LDLIBS_NVCRYPT) -L$(LIBNVCRYPT_PATH)

clean:
	rm -f *.o *~ core $(TARGET) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5) $(TARGET6)

.PHONY: clean

# Secure inline gateway - build with `make`, run unit tests with `make test`
CC      ?= gcc
CFLAGS  ?= -O2
CFLAGS  += -std=gnu11 -Wall -Wextra -Wshadow -D_GNU_SOURCE -fstack-protector-strong -D_FORTIFY_SOURCE=2
# Extra include dir for odd setups (e.g. make OPENSSL_INC=/path/include)
CFLAGS  += $(if $(OPENSSL_INC),-I$(OPENSSL_INC),)
CRYPTO_LIBS ?= -lcrypto
NFQ_CFLAGS  := $(shell pkg-config --cflags libnetfilter_queue 2>/dev/null)
NFQ_LIBS    := $(shell pkg-config --libs libnetfilter_queue 2>/dev/null || echo -lnetfilter_queue -lnfnetlink)

BUILD := build
LIB_SRC := src/crypto.c src/session.c src/packet.c src/handshake.c
LIB_OBJ := $(LIB_SRC:src/%.c=$(BUILD)/%.o)
TESTS   := $(BUILD)/test_crypto $(BUILD)/test_packet $(BUILD)/test_handshake

.PHONY: all test clean
all: $(BUILD)/secgw

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@
$(BUILD)/main.o: src/main.c | $(BUILD)
	$(CC) $(CFLAGS) $(NFQ_CFLAGS) -c $< -o $@
$(BUILD)/secgw: $(LIB_OBJ) $(BUILD)/main.o
	$(CC) $(CFLAGS) $^ -o $@ $(NFQ_LIBS) $(CRYPTO_LIBS) $(LDFLAGS)
$(BUILD)/test_%: tests/test_%.c $(LIB_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -Isrc $^ -o $@ $(CRYPTO_LIBS) $(LDFLAGS)
$(BUILD):
	mkdir -p $(BUILD)

test: $(TESTS)
	@set -e; for t in $(TESTS); do echo "== $$t"; $$t; done; echo "ALL UNIT TESTS PASSED"

clean:
	rm -rf $(BUILD)

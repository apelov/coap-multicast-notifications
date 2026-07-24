CC = clang
CFLAGS = -Wall -Wextra -O2 $(shell pkg-config --cflags libcoap-3 libcbor)
LDFLAGS = $(shell pkg-config --libs libcoap-3 libcbor)

SRCS_COMMON = src/cbor_helper.c src/oscore_helper.c
OBJS_COMMON = $(SRCS_COMMON:.c=.o)

SERVER_TARGET = coap_server
CLIENT_TARGET = coap_client

.PHONY: all clean

all: $(SERVER_TARGET) $(CLIENT_TARGET) libsocket_hook.dylib

$(SERVER_TARGET): src/server.o $(OBJS_COMMON)
	$(CC) $^ -o $@ $(LDFLAGS)

$(CLIENT_TARGET): src/client.o $(OBJS_COMMON)
	$(CC) $^ -o $@ $(LDFLAGS)

libsocket_hook.dylib: socket_hook.c
	$(CC) -Wall -Wextra -O2 -dynamiclib -o $@ $< -ldl

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(SERVER_TARGET) $(CLIENT_TARGET) libsocket_hook.dylib


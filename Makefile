CC = gcc
CFLAGS = -Wall -O2

BIN_DIR = bin

SERVER_SRCS = src/server/server.c src/server/user_auth.c src/server/crypto_sha.c src/server/server_log.c src/crypto_gcm.c
CLIENT_SRCS = src/client/client.c src/crypto_gcm.c
LOGDEC_SRCS = src/tools/log_decrypt.c

all: dirs secure_server secure_client log_decrypt

dirs:
	mkdir -p $(BIN_DIR)

secure_server:
	$(CC) $(CFLAGS) -o $(BIN_DIR)/secure_server $(SERVER_SRCS) -lpthread -lcrypto

secure_client:
	$(CC) $(CFLAGS) -o $(BIN_DIR)/secure_client $(CLIENT_SRCS) -lpthread -lcrypto

log_decrypt:
	$(CC) $(CFLAGS) -o $(BIN_DIR)/log_decrypt $(LOGDEC_SRCS) -lcrypto

clean:
	rm -rf $(BIN_DIR)

.PHONY: all clean

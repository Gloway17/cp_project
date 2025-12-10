#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
#include "crypto_sha.h"

void sha256(const unsigned char *data, int len, unsigned char *out)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(out, &ctx);
}

void sha256_hex(const char *input, char *output)
{
    unsigned char hash[32];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, input, strlen(input));
    SHA256_Final(hash, &ctx);

    for (int i = 0; i < 32; i++)
        sprintf(output + (i * 2), "%02x", hash[i]);

    output[64] = 0;
}

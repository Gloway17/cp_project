#ifndef CRYPTO_SHA_H
#define CRYPTO_SHA_H

void sha256(const unsigned char *data, int len, unsigned char *out);
void sha256_hex(const char *input, char *output);

#endif

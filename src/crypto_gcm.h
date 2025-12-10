#ifndef CRYPTO_GCM_H
#define CRYPTO_GCM_H

int aes_gcm_encrypt(
    const unsigned char *key,
    const unsigned char *plaintext, int plaintext_len,
    unsigned char *nonce,             // 12 bytes
    unsigned char *ciphertext,
    unsigned char *tag                // 16 bytes
);
int aes_gcm_decrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *tag,
    unsigned char *plaintext
);

#endif

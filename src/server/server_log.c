#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include "server_log.h"

static unsigned char LOG_KEY[32] = "0123456789ABCDEF0123456789ABCDEF";
static unsigned char IV[16]      = "0123456789ABCDEF";

void log_encrypted_msg(const unsigned char *msg, int len)
{
    FILE *fp = fopen("server_log.enc", "ab");
    if (!fp) return;

    unsigned char enc[1024];
    AES_KEY aes_key;
    AES_set_encrypt_key(LOG_KEY, 256, &aes_key);

    int block_cnt = (len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    int enc_len = block_cnt * AES_BLOCK_SIZE;

    unsigned char padded[1024];
    memcpy(padded, msg, len);
    memset(padded + len, AES_BLOCK_SIZE - (len % AES_BLOCK_SIZE),
           enc_len - len); // PKCS7 padding

    AES_cbc_encrypt(padded, enc, enc_len, &aes_key, IV, AES_ENCRYPT);

    fwrite(enc, 1, enc_len, fp);
    fclose(fp);
}

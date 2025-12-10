#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

static unsigned char LOG_KEY[32] = "0123456789ABCDEF0123456789ABCDEF";
static unsigned char IV[16]      = "0123456789ABCDEF";

void aes_decrypt(unsigned char *enc, int len) {
    AES_KEY aes_key;
    unsigned char out[1024];

    AES_set_decrypt_key(LOG_KEY, 256, &aes_key);
    AES_cbc_encrypt(enc, out, len, &aes_key, IV, AES_DECRYPT);

    int pad = out[len - 1]; // PKCS#7 padding
    if (pad > 0 && pad <= AES_BLOCK_SIZE) {
        len -= pad;
    }

    out[len] = '\0';
    printf("%s", out);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <encrypted_log_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("open");
        return 1;
    }

    unsigned char buf[1024];
    int len;

    while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
        // AES CBC는 블록단위라 len이 블록크기 배수일 것
        aes_decrypt(buf, len);
    }

    fclose(fp);
    return 0;
}

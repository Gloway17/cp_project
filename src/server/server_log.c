#include <openssl/evp.h>
#include <openssl/rand.h>
#include "server_log.h"

void encrypt_log_on_exit()
{
    FILE *in = fopen("chat_plain.log", "rb");
    if (!in) return;

    FILE *out = fopen("server_log.enc", "wb");
    if (!out) { fclose(in); return; }

    unsigned char key[32] = "0123456789ABCDEF0123456789ABCDEF";
    unsigned char iv[16];

    RAND_bytes(iv, 16);
    fwrite(iv, 1, 16, out); // 암호문 앞에 IV 저장

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024];
    unsigned char outbuf[1040];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, out);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    remove("chat_plain.log");  // 선택사항
}

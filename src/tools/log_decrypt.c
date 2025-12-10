#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

/*
 * server_log.enc 구조:
 * [0~15]  : IV
 * [16~ ]  : AES-CBC 암호문
 */

static unsigned char LOG_KEY[32] = "0123456789ABCDEF0123456789ABCDEF";

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

    // --- 1) IV 읽기 ---
    unsigned char iv[16];
    if (fread(iv, 1, 16, fp) != 16) {
        printf("Invalid encrypted log file.\n");
        fclose(fp);
        return 1;
    }

    // --- 2) 복호화 준비 ---
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, LOG_KEY, iv);

    unsigned char inbuf[1024];
    unsigned char outbuf[1040];
    int inlen, outlen;

    // --- 3) 암호문 전체를 읽어서 출력 ---
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), fp)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            printf("Decrypt update failed.\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(fp);
            return 1;
        }
        fwrite(outbuf, 1, outlen, stdout);
    }

    // --- 4) 마무리 (PKCS#7 패딩 제거) ---
    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        printf("Decrypt final failed (wrong key or tampered data).\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(fp);
        return 1;
    }

    fwrite(outbuf, 1, outlen, stdout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fp);

    return 0;
}

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include "crypto_sha.h"

void sha256_hex(const char *input, char *output)
{
    unsigned char hash[32];
    unsigned int hash_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return;

    // SHA-256 초기화
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    // 데이터 입력
    EVP_DigestUpdate(ctx, input, strlen(input));

    // 최종 해시 계산
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    EVP_MD_CTX_free(ctx);

    // hex 문자열 변환
    for (unsigned int i = 0; i < hash_len; i++)
        sprintf(output + (i * 2), "%02x", hash[i]);

    output[hash_len * 2] = '\0';   // 문자열 종료
}

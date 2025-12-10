#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

#include "crypto_gcm.h"

#define GCM_NONCE_LEN 12   // 권장값
#define GCM_TAG_LEN   16   // 권장값

/*
 * 입력:
 *   key (32 bytes)
 *   plaintext, plaintext_len
 *
 * 출력:
 *   nonce (12 bytes)
 *   ciphertext
 *   tag (16 bytes)
 *
 * 반환값:
 *   ciphertext_len (음수면 실패)
 */
int aes_gcm_encrypt(
    const unsigned char *key,
    const unsigned char *plaintext, int plaintext_len,
    unsigned char *nonce,             // 12 bytes
    unsigned char *ciphertext,
    unsigned char *tag                // 16 bytes
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    // 랜덤 nonce 생성
    RAND_bytes(nonce, GCM_NONCE_LEN);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    // key + nonce 설정
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    // 태그 생성
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}
/*
 * 입력:
 *   key (32 bytes)
 *   nonce (12 bytes)
 *   ciphertext, ciphertext_len
 *   tag (16 bytes)
 *
 * 출력:
 *   plaintext
 *
 * 반환값:
 *   plaintext_len (음수면 태그 불일치 → 변조됨)
 */
int aes_gcm_decrypt(
    const unsigned char *key,
    const unsigned char *nonce,
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *tag,
    unsigned char *plaintext
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    // key + nonce 설정
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    // 태그 설정
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag);

    // 복호화 최종 단계: 태그 검사 포함
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;  // 태그 불일치 → 변조된 메시지
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

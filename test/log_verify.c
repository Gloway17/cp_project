#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/common/protocol.h"
#include "../src/common/utils.h"
#include "../src/crypto/crypto_util.h"
#include <openssl/rand.h>

unsigned char ENC_KEY[32];
unsigned char MAC_KEY[32];

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s log_file\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char pw[] = "pass1234";
    unsigned char salt_key[16];

    printf("[+] Enter salt_key(32 hex chars): ");
    for (int i = 0; i < 16; i++)
        scanf("%2hhx", &salt_key[i]);

    derive_keys(pw, salt_key, ENC_KEY, MAC_KEY);

    while (!feof(fp)) {
        PacketHeader hdr;
        if (fread(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr))
            break;

        int body_len = hdr.body_len;
        unsigned char *buf = malloc(body_len);
        fread(buf, 1, body_len, fp);

        unsigned char *iv = buf;
        unsigned char *cipher = buf + 16;
        int ct_len = body_len - 16 - 32;
        unsigned char *hmac = buf + 16 + ct_len;

        unsigned char calc_hmac[32];
        make_hmac(cipher, ct_len, MAC_KEY, calc_hmac);

        if (memcmp(hmac, calc_hmac, 32) != 0) {
            printf("[!] Tampered message detected!\n");
            free(buf);
            continue;
        }

        unsigned char plain[1024];
        int pt_len =
            aes_decrypt(cipher, ct_len, ENC_KEY, iv, plain);
        plain[pt_len] = '\0';

        printf("[Msg] %s\n", plain);
        free(buf);
    }

    fclose(fp);
    return 0;
}

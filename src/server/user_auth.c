#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "crypto_sha.h"

typedef struct {
    char id[32];
    char salt[32];
    char hash[65];
} UserInfo;

static UserInfo users[128];
static int user_count = 0;

void load_users() {
    FILE *f = fopen("users.txt", "r");
    if (!f) {
        perror("users.txt not found");
        return;
    }

    while(fscanf(f, "%[^:]:%[^:]:%s\n",
                 users[user_count].id,
                 users[user_count].salt,
                 users[user_count].hash) == 3)
    {
        user_count++;
    }
    fclose(f);

    printf("[Server] %d users loaded.\n", user_count);
}

int verify_user(const char *id, const char *pw) {
    char input_hash[65];
    char combined[128];

    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].id, id) == 0) {
            sprintf(combined, "%s%s", pw, users[i].salt);
            sha256_hex(combined, input_hash);
            return strcmp(users[i].hash, input_hash) == 0;
        }
    }

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "../crypto_gcm.h"

#define BUF_SIZE 100
#define NAME_SIZE 20

void send_encrypted(int sock, const char *msg);
void *send_msg(void *arg);
void *recv_msg(void *arg);
void error_handling(char *msg);

char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE];
unsigned char session_key[32];

int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in serv_addr;
    pthread_t snd_thread, rcv_thread;
    void *thread_return;
    char buf[BUF_SIZE];

    if(argc != 3) {
        printf("Usage : %s <IP> <port>\n", argv[0]);
        exit(1);
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if(sock == -1) error_handling("socket() error");

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    // --- AUTH PHASE ---
    recv(sock, buf, BUF_SIZE, 0); // "ID: "
    fputs(buf, stdout);
    fgets(msg, BUF_SIZE, stdin);
    write(sock, msg, strlen(msg));

    msg[strcspn(msg, "\n")] = 0;
    snprintf(name, NAME_SIZE, "[%s]", msg);  // ★ ID를 바로 nickname 으로 사용

    recv(sock, buf, BUF_SIZE, 0); // "PW: "
    fputs(buf, stdout);
    fgets(msg, BUF_SIZE, stdin);
    write(sock, msg, strlen(msg));

    recv(sock, buf, BUF_SIZE, 0); // AUTH result
    buf[strcspn(buf, "\n")] = 0;
    printf("%s\n", buf);

    if (strcmp(buf, "Auth Success") != 0) {
        printf("[Client] Authentication failed. exit.\n");
        close(sock);
        exit(0);
    }

    // 세션키 수신
    int len = read(sock, session_key, 32);
    if (len != 32) {
        printf("Session key receive failed\n");
        exit(1);
    }

    printf("[Client] Session key received.\n");

    // --- CHAT PHASE ---
    pthread_create(&snd_thread, NULL, send_msg, (void*)&sock);
    pthread_create(&rcv_thread, NULL, recv_msg, (void*)&sock);

    pthread_join(snd_thread, &thread_return);
    pthread_join(rcv_thread, &thread_return);

    close(sock);
    return 0;
}

void send_encrypted(int sock, const char *msg)
{
    unsigned char nonce[12];
    unsigned char ciphertext[1024];
    unsigned char tag[16];

    int ct_len = aes_gcm_encrypt(
        session_key,
        (unsigned char *)msg, strlen(msg),
        nonce,
        ciphertext,
        tag
    );

    uint32_t n = htonl(ct_len);

    write(sock, nonce, 12);
    write(sock, &n, 4);
    write(sock, ciphertext, ct_len);
    write(sock, tag, 16);
}

void *send_msg(void *arg)
{
    int sock = *((int*)arg);
    char buffer[1024];
    char formatted[2048];

    while (1) {
        fgets(buffer, sizeof(buffer), stdin);
        // buffer[strcspn(buffer, "\n")] = 0;   // 개행 제거

        if (!strcmp(buffer, "q\n") || !strcmp(buffer, "Q\n")) {
            close(sock);
            exit(0);
        }

        // [ID] 메시지 형태로 포맷팅 → 암호화하기 전 평문 구성
        snprintf(formatted, sizeof(formatted), "%s %s", name, buffer);

        // 완성된 평문을 암호화하여 전송
        send_encrypted(sock, formatted);
    }
}

void *recv_msg(void *arg)
{
    int sock = *((int*)arg);
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char ciphertext[2048];
    unsigned char plaintext[2048];

    while (1) {
        // 1) nonce 읽기
        if (read(sock, nonce, 12) <= 0) break;

        // 2) ciphertext 길이
        uint32_t ct_len_net;
        read(sock, &ct_len_net, 4);
        int ct_len = ntohl(ct_len_net);

        // 3) ciphertext + tag
        read(sock, ciphertext, ct_len);
        read(sock, tag, 16);

        // 4) 복호화
        int pt_len = aes_gcm_decrypt(
            session_key, 
            nonce, 
            ciphertext, ct_len,
            tag, 
            plaintext
        );

        if (pt_len < 0) {
            printf("[!] Tampered message detected\n");
            continue;
        }

        plaintext[pt_len] = '\0';
        printf("%s", plaintext);
    }
    return NULL;
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

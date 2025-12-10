#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/rand.h>

#include "user_auth.h"
#include "server_log.h"
#include "../crypto_gcm.h"

#define BUF_SIZE 100
#define MAX_CLNT 256

void broadcast_encrypted(int from_sock, const char *msg);
void *handle_clnt(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *msg);

static void handle_exit_signal(int sig);

int clnt_cnt = 0;
int clnt_socks[MAX_CLNT];
unsigned char client_keys[MAX_CLNT][32];
pthread_mutex_t mutx;

int main(int argc, char *argv[])
{
    int serv_sock, clnt_sock;
    struct sockaddr_in serv_adr, clnt_adr;
    socklen_t clnt_adr_sz;
    pthread_t t_id;

    if(argc != 2) {
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    signal(SIGINT, handle_exit_signal);   // Ctrl+C

    pthread_mutex_init(&mutx, NULL);
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if(serv_sock == -1) error_handling("socket() error");

    load_users();
    printf("[Server] user list loaded.\n");

    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if(bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");

    if(listen(serv_sock, 5) == -1)
        error_handling("listen() error");

    printf("[Server] Listening on %s:%s\n", "0.0.0.0", argv[1]);

    while(1)
    {
        clnt_adr_sz = sizeof(clnt_adr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        if(clnt_sock < 0) continue;

        printf("[Server] Client connected : %s\n", inet_ntoa(clnt_adr.sin_addr));

        // ------------------- AUTH PHASE --------------------
        char id[BUF_SIZE], pw[BUF_SIZE];

        write(clnt_sock, "ID: ", 4);
        int len = read(clnt_sock, id, sizeof(id) - 1);
        if(len <= 0) { close(clnt_sock); continue; }
        id[strcspn(id, "\n")] = 0;

        write(clnt_sock, "PW: ", 4);
        len = read(clnt_sock, pw, sizeof(pw) - 1);
        if(len <= 0) { close(clnt_sock); continue; }
        pw[strcspn(pw, "\n")] = 0;

        if(!verify_user(id, pw)) {
            write(clnt_sock, "Auth Failed\n", 12);
            printf("[Server] Auth Fail: ID=%s PW=%s\n", id, pw);
            close(clnt_sock);
            continue;
        }

        write(clnt_sock, "Auth Success\n", 13);
        printf("[Server] Auth Success => %s\n", inet_ntoa(clnt_adr.sin_addr));
        // ----------------------------------------------------
        // session_key 생성 및 전송
        unsigned char session_key[32];
        RAND_bytes(session_key, 32);

        // 클라이언트에게 전송
        write(clnt_sock, session_key, 32);

        // 서버 내부에 저장할 필요가 있으면 배열 사용
        memcpy(client_keys[clnt_sock], session_key, 32);
        // ----------------------------------------------------

        pthread_mutex_lock(&mutx);
        clnt_socks[clnt_cnt++] = clnt_sock;
        pthread_mutex_unlock(&mutx);

        pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);
        pthread_detach(t_id);
    }
    close(serv_sock);
    return 0;
}

void broadcast_encrypted(int from_sock, const char *msg)
{
    // -----------------------------
    // 1) 평문 로그 저장
    // -----------------------------
    FILE *fp = fopen("chat_plain.log", "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", t);
        fprintf(fp, "[%s] %s\n", ts, msg);
        fclose(fp);
    }

    // -----------------------------
    // 2) 암호문 브로드캐스트
    // -----------------------------
    for (int i = 0; i < clnt_cnt; i++) {
        if (clnt_socks[i] == from_sock) continue;

        unsigned char nonce[12], tag[16], ciphertext[2048];
        int ct_len = aes_gcm_encrypt(
            client_keys[clnt_socks[i]],
            (unsigned char*)msg, strlen(msg),
            nonce, ciphertext, tag);

        uint32_t n = htonl(ct_len);

        write(clnt_socks[i], nonce, 12);
        write(clnt_socks[i], &n, 4);
        write(clnt_socks[i], ciphertext, ct_len);
        write(clnt_socks[i], tag, 16);
    }
}

void *handle_clnt(void *arg)
{
    int clnt_sock = *((int*)arg);

    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char ciphertext[2048];
    unsigned char plaintext[2048];

    while (1)
    {
        // -------------------------
        // 1) nonce 읽기
        // -------------------------
        int n = read(clnt_sock, nonce, 12);
        if (n <= 0) break;

        // -------------------------
        // 2) 암호문 길이 읽기
        // -------------------------
        uint32_t ct_len_net;
        if (read(clnt_sock, &ct_len_net, 4) <= 0) break;
        int ct_len = ntohl(ct_len_net);

        // 안전성 체크
        if (ct_len <= 0 || ct_len > 2000) break;

        // -------------------------
        // 3) ciphertext 읽기
        // -------------------------
        if (read(clnt_sock, ciphertext, ct_len) <= 0) break;

        // -------------------------
        // 4) tag 읽기
        // -------------------------
        if (read(clnt_sock, tag, 16) <= 0) break;

        // -------------------------
        // 5) 복호화
        // -------------------------
        int pt_len = aes_gcm_decrypt(
            client_keys[clnt_sock],   // 로그인 단계에서 저장된 세션키
            nonce,
            ciphertext,
            ct_len,
            tag,
            plaintext
        );

        if (pt_len < 0) {
            printf("[Server] Tampered / invalid message from %d\n", clnt_sock);
            continue; 
        }

        plaintext[pt_len] = '\0';   // 문자열 종료

        // -------------------------
        // 6) 서버 콘솔 출력 & 재암호화 브로드캐스트
        // -------------------------
        printf("%s", plaintext);

        broadcast_encrypted(clnt_sock, (char*)plaintext);
    }

    // ------------------------------
    // 7) 클라이언트 종료 처리
    // ------------------------------
    pthread_mutex_lock(&mutx);
    for (int i = 0; i < clnt_cnt; i++) {
        if (clnt_sock == clnt_socks[i]) {
            while (i++ < clnt_cnt - 1)
                clnt_socks[i] = clnt_socks[i + 1];
            break;
        }
    }
    clnt_cnt--;
    pthread_mutex_unlock(&mutx);

    close(clnt_sock);
    return NULL;
}

void send_msg(char *msg, int len)
{
    int i;

    // ---------------------------------------------------
    // [1] 평문 로그 저장 (서버 종료 시 CBC 암호화)
    // ---------------------------------------------------
    FILE *fp = fopen("chat_plain.log", "a");
    if (fp) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

        fprintf(fp, "[%s] %.*s", timestamp, len, msg);
        fclose(fp);
    }

    // ---------------------------------------------------
    // [2] 모든 클라이언트에게 암호문으로 전송 (AES-GCM)
    // ---------------------------------------------------
    pthread_mutex_lock(&mutx);

    for (i = 0; i < clnt_cnt; i++)
    {
        int sock = clnt_socks[i];

        unsigned char nonce[12];
        unsigned char tag[16];
        unsigned char ciphertext[2048];

        int ct_len = aes_gcm_encrypt(
            client_keys[sock],          // 클라이언트 세션키
            (unsigned char*)msg,
            len,
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

    pthread_mutex_unlock(&mutx);
}

static void handle_exit_signal(int sig)
{
    printf("\n[Server] Caught signal %d, encrypting logs...\n", sig);

    encrypt_log_on_exit();

    printf("[Server] Logs encrypted. Shutting down.\n");

    exit(0);
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

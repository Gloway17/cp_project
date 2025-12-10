#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "user_auth.h"
#include "server_log.h"

#define BUF_SIZE 100
#define MAX_CLNT 256

void *handle_clnt(void *arg);
void send_msg(char *msg, int len);
void error_handling(char *msg);

int clnt_cnt = 0;
int clnt_socks[MAX_CLNT];
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

        pthread_mutex_lock(&mutx);
        clnt_socks[clnt_cnt++] = clnt_sock;
        pthread_mutex_unlock(&mutx);

        pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);
        pthread_detach(t_id);
    }
    close(serv_sock);
    return 0;
}

void *handle_clnt(void *arg)
{
    int clnt_sock = *((int*)arg);
    int str_len, i;
    char msg[BUF_SIZE];

    while((str_len = read(clnt_sock, msg, sizeof(msg))) > 0)
        send_msg(msg, str_len);

    pthread_mutex_lock(&mutx);
    for(i = 0; i < clnt_cnt; i++) {
        if(clnt_sock == clnt_socks[i]) {
            while(i++ < clnt_cnt - 1)
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
    pthread_mutex_lock(&mutx);

    // 1) 타임스탬프 생성
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    // 2) 메시지 재구성: "[timestamp] msg"
    char formatted_msg[BUF_SIZE + 64];
    int flen = snprintf(formatted_msg, sizeof(formatted_msg),
                        "[%s] %.*s", timestamp, len, msg);

    // 3) 암호화 로그 저장
    log_encrypted_msg((unsigned char *)formatted_msg, flen);

    // 4) 모든 클라이언트에게 timestamp 포함 메시지 전송
    for (int i = 0; i < clnt_cnt; i++)
        write(clnt_socks[i], formatted_msg, flen);

    pthread_mutex_unlock(&mutx);
}


void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#define BUF_SIZE 100
#define NAME_SIZE 20

void *send_msg(void *arg);
void *recv_msg(void *arg);
void error_handling(char *msg);

char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE];

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

    // --- CHAT PHASE ---
    pthread_create(&snd_thread, NULL, send_msg, (void*)&sock);
    pthread_create(&rcv_thread, NULL, recv_msg, (void*)&sock);

    pthread_join(snd_thread, &thread_return);
    pthread_join(rcv_thread, &thread_return);

    close(sock);
    return 0;
}

void *send_msg(void *arg)
{
    int sock = *((int*)arg);
    char name_msg[NAME_SIZE + BUF_SIZE];

    while(1)
    {
        fgets(msg, BUF_SIZE, stdin);

        if(!strcmp(msg, "q\n") || !strcmp(msg, "Q\n"))
        {
            close(sock);
            exit(0);
        }

        sprintf(name_msg, "%s %s", name, msg);
        write(sock, name_msg, strlen(name_msg));
    }
    return NULL;
}

void *recv_msg(void *arg)
{
    int sock = *((int*)arg);
    char name_msg[NAME_SIZE + BUF_SIZE];
    int str_len;

    while(1)
    {
        str_len = read(sock, name_msg, NAME_SIZE + BUF_SIZE - 1);
        if(str_len <= 0)
            return (void*)-1;

        name_msg[str_len] = 0;
        fputs(name_msg, stdout);
    }
    return NULL;
}

void error_handling(char *msg)
{
    fputs(msg, stderr);
    fputc('\n', stderr);
    exit(1);
}

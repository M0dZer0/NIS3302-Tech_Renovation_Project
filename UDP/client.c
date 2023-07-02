/* File Name: client.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <pthread.h>

#define MAXLINE 4096

struct sockaddr_in servaddr;
fd_set rset;
int serverSocket, n, rec_len;
pthread_t receiveThread, sendThread;

void *receiveMessage(void *arg)
{
    char buffer[MAXLINE];
    while (1)
    {
        memset(buffer, 0, MAXLINE);
        if ((rec_len = recvfrom(serverSocket, buffer, MAXLINE, 0, NULL, NULL)) == -1)
        {
            perror("Error while receiving message");
            exit(1);
        }
        buffer[rec_len] = '\0';
        // 清除本行并打印接收到的消息
        printf("\r\033[KReceived message from server: %s\n", buffer);

        // 光标上移一行
        printf("\033[A");

        // 打印 "Enter your message to client: " 并等待输入
        printf("Enter your message to server: ");
        fflush(stdout);
    }
    pthread_exit(NULL);
}
void *sendMessage(void *arg)
{
    char buffer[MAXLINE];
    while (1)
    {
        printf("Enter your message to server: ");
        fgets(buffer, MAXLINE, stdin);
        if (sendto(serverSocket, buffer, strlen(buffer), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        {
            printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
            exit(0);
        }
    }
    pthread_exit(NULL);
}
int main(int argc, char **argv)
{

    char recvline[4096], sendline[4096];
    char buf[MAXLINE];

    int maxfdp1;
    struct timeval tv;

    if (argc != 2)
    {
        printf("usage: ./client <ipaddress>\n");
        exit(0);
    }

    if ((serverSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8000);
    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0)
    {
        printf("inet_pton error for %s\n", argv[1]);
        exit(0);
    }
    printf("Connected to server\n");
    
    // 创建接收和发送消息的线程
    if (pthread_create(&receiveThread, NULL, receiveMessage, NULL) != 0)
    {
        perror("Failed to create receive thread");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&sendThread, NULL, sendMessage, NULL) != 0)
    {
        perror("Failed to create send thread");
        exit(EXIT_FAILURE);
    }

    // 等待线程结束
    pthread_join(receiveThread, NULL);
    pthread_join(sendThread, NULL);
    close(serverSocket);
    return 0;
}

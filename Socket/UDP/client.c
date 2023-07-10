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
#include "key_generate.h"
#include <unistd.h>

#define BUFFER_SIZE 1024
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

        if (strcmp(buffer, "exit") == 0)
        {
            printf("\r\033[K");
            printf("Server requested to exit.\n");
            close(serverSocket);
            clear();
            exit(0);
        }

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
        // 检测回车内容
        if (strcmp(buffer, "\n") == 0)
        {
            // 询问用户是否退出程序
            printf("Do you want to exit the program? (y/n): ");
            fflush(stdout);
            char answer[BUFFER_SIZE];
            fgets(answer, BUFFER_SIZE, stdin);

            if (strcmp(answer, "y\n") == 0 || strcmp(answer, "Y\n") == 0)
            {
                // 发送退出消息给客户端
                ssize_t bytesSent = sendto(serverSocket, "exit", strlen("exit"), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
                if (bytesSent <= 0)
                {
                    perror("Error while sending exit message");
                }
                clear();
                exit(0); // 退出发送消息的循环
            }
        }
        else
        {
            ssize_t bytesSent = sendto(serverSocket, buffer, strlen(buffer), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
            if (bytesSent <= 0)
            {
                printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
                exit(0);
            }
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

    if (argc != 3)
    {
        printf("usage: %s <ipaddress> <port>\n", argv[0]);
        exit(0);
    }

    if ((serverSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(atoi(argv[2]));
    if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0)
    {
        printf("inet_pton error for %s\n", argv[1]);
        exit(0);
    }
    printf("Connected to server\n");

    // 判断public_key.der和private_key.der是否存在，若不存在则生成密钥，并存入文件
    if (access("public_key.der", F_OK) == -1 || access("private_key.der", F_OK) == -1)
    {
        setKey();
        struct key pub_key = convert_file("public_key.der");
        struct key pri_key = convert_file("private_key.der");

        printf("generate key successfully!\n");

        /*
        hex_print(pub_key);
        printf("the length of pub_key: %d\n", pub_key.length);
        hex_print(pri_key);
        printf("the length of pri_key: %d\n", pri_key.length);
        */

        // 保存key到文件中
        save_key_to_file("pub_key_file", pub_key);
        save_key_to_file("pri_key_file", pri_key);

        /*
                // 将公钥长度和公钥内容发送给服务器
                char pub_key_length[4];
                sprintf(pub_key_length, "%d", pub_key.length);
                //将公钥长度放在公钥内容前
                char *pub_key_data;
                memcpy(pub_key_data, pub_key_length, 4);
                memcpy(pub_key_data + 4, pub_key.data, pub_key.length);
                ssize_t bytesSent = send(serverSocket, pub_key_data, pub_key.length + 4, 0);
                if (bytesSent <= 0)
                {
                    perror("Error while sending public key to server");
                }

                // 接收服务器的公钥
                char buffer[BUFFER_SIZE];
                memset(buffer, 0, BUFFER_SIZE);
                ssize_t bytesRead = recv(serverSocket, buffer, BUFFER_SIZE, 0);
                if (bytesRead <= 0)
                {
                    perror("Error while receiving public key from server");
                }

                //读取公钥长度信息
                struct key server_pub_key;
                char server_pub_key_length[4];
                memcpy(server_pub_key_length, buffer, 4);
                //将公钥长度转换为int类型
                int server_pub_key_length_int = atoi(server_pub_key_length);
                server_pub_key.length = server_pub_key_length_int;
                //读取公钥内容
                memcpy(server_pub_key.data, buffer + 4, server_pub_key_length_int);
                //将公钥内容保存到文件中
                save_key_to_file("server_pub_key_file", server_pub_key);
        */
        // 将公钥发送给服务器
        ssize_t bytesSent = sendto(serverSocket, pub_key.data, pub_key.length, 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
        if (bytesSent <= 0)
        {
            perror("Error while sending public key to server");
        }

        // 接收服务器的公钥
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (bytesRead <= 0)
        {
            perror("Error while receiving public key from server");
        }

        // 将公钥内容保存到文件中
        struct key server_pub_key;
        server_pub_key.length = bytesRead;
        server_pub_key.data = malloc(bytesRead);
        memcpy(server_pub_key.data, buffer, bytesRead);
        save_key_to_file("server_pub_key_file", server_pub_key);

        hex_print(server_pub_key);
        // 清空命令行显示
        printf("\r\033[K");
    }

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
    clear();
    printf("\033[A");
    printf("\r\033[K");
    return 0;
}
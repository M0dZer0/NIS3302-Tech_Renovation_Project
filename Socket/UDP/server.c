/* File Name: server.c */
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

#define DEFAULT_PORT 8000
#define MAXLINE 4096
#define BUFFER_SIZE 1024

struct sockaddr_in servaddr,
    cliaddr;
int serverSocket;
pthread_t receiveThread, sendThread;

void *receiveMessage(void *arg)
{
    int n;
    char buffer[MAXLINE];
    socklen_t len = sizeof(cliaddr);

    while (1)
    {
        memset(buffer, 0, MAXLINE);
        n = recvfrom(serverSocket, buffer, MAXLINE, 0, (struct sockaddr *)&cliaddr, &len);
        if (n <= 0)
        {
            perror("Error while receiving message");
            break;
        }

        if (strcmp(buffer, "exit") == 0)
        {
            printf("\r\033[K");
            printf("Client requested to exit.\n");
            close(serverSocket);
            clear();
            exit(0);
        }

        printf("\r\033[KReceived message from client: %s\n", buffer);
        printf("\033[A");
        printf("Enter your message to client: ");
        fflush(stdout);
    }
    pthread_exit(NULL);
}

void *sendMessage(void *arg)
{
    char buffer[MAXLINE];
    socklen_t len = sizeof(cliaddr);

    while (1)
    {
        printf("Enter your message to client: ");
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
                ssize_t bytesSent = sendto(serverSocket, "exit", strlen("exit"), 0, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
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
            ssize_t bytesSent = sendto(serverSocket, buffer, strlen(buffer), 0, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
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
    // Initialize Socket
    if ((serverSocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }
    if (argc != 2)
    {
        printf("usage: %s <port>\n", argv[0]);
        exit(0);
    }

    // Initialize server address
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // Set IP address to INADDR_ANY to automatically get the local IP address
    servaddr.sin_port = htons(atoi(argv[1]));     // Set the port to DEFAULT_PORT

    // Bind the local address to the created socket
    if (bind(serverSocket, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
    {
        printf("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening for incoming connections...\n");

    // 判断public_key.der和private_key.der是否存在，若不存在则生成密钥，并存入文件
    if (access("public_key.der", F_OK) == -1 || access("private_key.der", F_OK) == -1)
    {
        setKey();
        struct key pub_key = convert_file("public_key.der");
        struct key pri_key = convert_file("private_key.der");

        printf("generate key successfully!\n");
        /*
        printf("pub_key: %s\n", pub_key.data);
        printf("the length of pub_key: %d\n", pub_key.length);
        printf("pri_key: %s\n", pri_key.data);
        printf("the length of pri_key: %d\n", pri_key.length);
        */

        // 保存key到文件中
        save_key_to_file("pub_key_file", pub_key);
        save_key_to_file("pri_key_file", pri_key);

        /*
                // 将公钥长度和公钥内容发送给客户端
                char pub_key_length[4];
                sprintf(pub_key_length, "%d", pub_key.length);
                //将公钥长度放在公钥内容前
                char *pub_key_data;
                memcpy(pub_key_data, pub_key_length, 4);
                memcpy(pub_key_data + 4, pub_key.data, pub_key.length);
                ssize_t bytesSent = send(clientSocket, pub_key_data, pub_key.length + 4, 0);
                if (bytesSent <= 0)
                {
                    perror("Error while sending public key to client");
                }

                // 接收客户端的公钥
                char buffer[BUFFER_SIZE];
                memset(buffer, 0, BUFFER_SIZE);
                ssize_t bytesRead = recv(clientSocket, buffer, BUFFER_SIZE, 0);
                if (bytesRead <= 0)
                {
                    perror("Error while receiving public key from client");
                }

                //读取公钥长度信息
                struct key client_pub_key;
                char client_pub_key_length[4];
                memcpy(client_pub_key_length, buffer, 4);
                //将公钥长度转换为int类型
                int client_pub_key_length_int = atoi(client_pub_key_length);
                client_pub_key.length = client_pub_key_length_int;
                //读取公钥内容
                memcpy(client_pub_key.data, buffer + 4, client_pub_key_length_int);
                //将公钥内容保存到文件中
                save_key_to_file("client_pub_key_file", client_pub_key);
        */

        // 接收客户端的公钥
        char buffer[BUFFER_SIZE];
        socklen_t len = sizeof(cliaddr);

        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&cliaddr, &len);
        if (bytesRead <= 0)
        {
            perror("Error while receiving public key from client");
        }

        // 将公钥内容保存到文件中
        struct key client_pub_key;
        client_pub_key.length = bytesRead;
        client_pub_key.data = malloc(bytesRead);
        memcpy(client_pub_key.data, buffer, bytesRead);
        save_key_to_file("client_pub_key_file", client_pub_key);

        hex_print(client_pub_key);

        // 将公钥发送给客户端
        ssize_t bytesSent = sendto(serverSocket, pub_key.data, pub_key.length, 0, (struct sockaddr *)&cliaddr, sizeof(cliaddr));
        if (bytesSent <= 0)
        {
            perror("Error while sending public key to client");
        }

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
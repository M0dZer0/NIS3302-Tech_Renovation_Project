#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define BUFFER_SIZE 4096

int serverSocket;
pthread_t receiveThread, sendThread;

// 接收消息的线程
void *receiveMessage(void *arg)
{
    char buffer[BUFFER_SIZE];

    while (1)
    {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead = recv(serverSocket, buffer, BUFFER_SIZE, 0);
        if (bytesRead <= 0)
        {
            perror("Error while receiving message");
            break;
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

// 发送消息的线程
void *sendMessage(void *arg)
{
    char buffer[BUFFER_SIZE];

    while (1)
    {
        printf("Enter your message to server: ");
        fgets(buffer, BUFFER_SIZE, stdin);
        ssize_t bytesSent = send(serverSocket, buffer, strlen(buffer), 0);
        if (bytesSent <= 0)
        {
            perror("Error while sending message");
            break;
        }
    }

    pthread_exit(NULL);
}

int main(int argc, char **argv)
{
    struct sockaddr_in serverAddr;
    char buffer[BUFFER_SIZE];
    if (argc != 2)
    {
        printf("usage: ./client <ipaddress>\n");
        exit(0);
    }

    // 创建TCP套接字
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器IP和端口
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(argv[1]); // 指定服务器IP
    serverAddr.sin_port = htons(8000);               // 指定服务器端口

    // 连接服务器
    if (connect(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        perror("Connection failed");
        exit(EXIT_FAILURE);
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

    // 关闭套接字
    close(serverSocket);

    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define BUFFER_SIZE 1024
#define DEFAULT_PORT 8000

int clientSocket;
pthread_t receiveThread, sendThread;

// 接收消息的线程
void *receiveMessage(void *arg)
{
    char buffer[BUFFER_SIZE];

    while (1)
    {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytesRead = recv(clientSocket, buffer, BUFFER_SIZE, 0);
        if (bytesRead <= 0)
        {
            perror("Error while receiving message");
            break;
        }

        // 清除本行并打印接收到的消息
        printf("\r\033[KReceived message from client: %s\n", buffer);

        // 光标上移一行
        printf("\033[A");

        // 打印 "Enter your message to client: " 并等待输入
        printf("Enter your message to client: ");
        fflush(stdout); // 刷新输出缓冲区，以便立即显示
    }

    pthread_exit(NULL);
}
// 发送消息的线程
void *sendMessage(void *arg)
{
    char buffer[BUFFER_SIZE];

    while (1)
    {

        printf("Enter your message to client: ");

        fgets(buffer, BUFFER_SIZE, stdin);
        ssize_t bytesSent = send(clientSocket, buffer, strlen(buffer), 0);
        if (bytesSent <= 0)
        {
            perror("Error while sending message");
            break;
        }
    }

    pthread_exit(NULL);
}
int main()
{
    int serverSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);

    // 创建TCP套接字
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 设置服务器IP和端口
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(DEFAULT_PORT);

    // 绑定IP地址和端口号
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        perror("Binding failed");
        exit(EXIT_FAILURE);
    }

    // 监听连接
    if (listen(serverSocket, 1) < 0)
    {
        perror("Listening failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening for incoming connections...\n");

    // 接受客户端连接
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addrLen);
    if (clientSocket < 0)
    {
        perror("Accepting connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Client connected: %s\n", inet_ntoa(clientAddr.sin_addr));

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
    close(clientSocket);
    close(serverSocket);

    return 0;
}

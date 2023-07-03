#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "key_generate.h"

#define BUFFER_SIZE 1024

int clientSocket;
pthread_t receiveThread, sendThread;

void print_key(struct key key)
{
}
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

        if (strcmp(buffer, "exit") == 0)
        {
            printf("Client requested to exit.\n");
            close(clientSocket);
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
    serverAddr.sin_port = htons(8000);

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

    // 判断public_key.der和private_key.der是否存在，若不存在则生成密钥，并存入文件
    if (access("public_key.der", F_OK) == -1 || access("private_key.der", F_OK) == -1)
    {
        setKey();
        struct key pub_key = convert_file("public_key.der");
        struct key pri_key = convert_file("private_key.der");

        printf("generate key successfully!\n");

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

        // 将公钥发送给客户端
        ssize_t bytesSent = send(clientSocket, pub_key.data, pub_key.length, 0);
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

        // 将公钥内容保存到文件中
        struct key client_pub_key;
        client_pub_key.length = bytesRead;
        client_pub_key.data = malloc(bytesRead); // 分配足够的内存空间
        memcpy(client_pub_key.data, buffer, bytesRead);
        save_key_to_file("client_pub_key_file", client_pub_key);
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

    // 关闭套接字
    close(clientSocket);
    close(serverSocket);

    return 0;
}
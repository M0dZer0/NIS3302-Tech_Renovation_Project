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

int serverSocket;
pthread_t receiveThread, sendThread;
// 退出时清除产生的文件
void clear()
{
    remove("public_key.der");
    remove("private_key.der");
    remove("pub_key_file");
    remove("pri_key_file");
    remove("server_pub_key_file");
}
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

        if (strcmp(buffer, "exit") == 0)
        {
            printf("Server requested to exit.\n");
            close(serverSocket);
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
        ssize_t bytesSent = send(serverSocket, pub_key.data, pub_key.length, 0);
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

        // 将公钥内容保存到文件中
        struct key server_pub_key;
        server_pub_key.length = bytesRead;
        server_pub_key.data = malloc(bytesRead); // 分配足够的内存空间
        memcpy(server_pub_key.data, buffer, bytesRead);
        save_key_to_file("server_pub_key_file", server_pub_key);

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
    close(serverSocket);
    clear();

    return 0;
}
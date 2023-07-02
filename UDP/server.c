/* File Name: server.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define DEFAULT_PORT 8000
#define MAXLINE 4096

struct sockaddr_in servaddr, cliaddr;
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
        // Send data back to the client using sendto() function
        if (sendto(serverSocket, buffer, strlen(buffer), 0, (struct sockaddr *)&cliaddr, len) == -1)
        {
            printf("sendto error: %s(errno: %d)\n", strerror(errno), errno);
            exit(0);
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

    // Initialize server address
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // Set IP address to INADDR_ANY to automatically get the local IP address
    servaddr.sin_port = htons(DEFAULT_PORT);      // Set the port to DEFAULT_PORT

    // Bind the local address to the created socket
    if (bind(serverSocket, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
    {
        printf("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening for incoming connections...\n");

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
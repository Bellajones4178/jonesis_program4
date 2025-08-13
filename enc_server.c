#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>

// turn a char into a number
int charToNum(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c == ' ') return 26;
    return -1;
}

// turn a number back into a char
char numToChar(int n) {
    if (n >= 0 && n < 26) return 'A' + n;
    if (n == 26) return ' ';
    return '?';
}

// take my plaintext + key, do mod 27 and calculate encrypted version
void encrypt(const char *plainTxt, const char *keyTxt, char *cipherTxt) {
    int i;
    for (i = 0; plainTxt[i] != '\0'; i++) {
        int pNum = charToNum(plainTxt[i]);
        int kNum = charToNum(keyTxt[i]);
        int cNum = (pNum + kNum) % 27;
        cipherTxt[i] = numToChar(cNum);
    }
    cipherTxt[i] = '\0';
}

// bail with an error
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// pull exactly len bytes
void recvAll(int fd, char *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) { perror("recv"); exit(1); }
        got += n;
    }
}

// send exactly len bytes
void sendAll(int fd, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) { perror("send"); exit(1); }
        sent += n;
    }
}

// reap zombie kids
void handleChild(int signo) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *argv[]) {
    int listenSock, connectSock, portNum;
    socklen_t clientSize;
    char hsBuf[16];
    struct sockaddr_in servAddr, clientAddr;

    if (argc < 2) { fprintf(stderr, "USAGE: %s port\n", argv[0]); exit(1); }

    // set up sigchld so we don’t leak zombies
    struct sigaction sa;
    sa.sa_handler = handleChild;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    // set up address struct
    memset((char *)&servAddr, '\0', sizeof(servAddr));
    portNum = atoi(argv[1]);
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(portNum);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    // open socket
    listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) error("ERROR opening socket");

    // bind socket
    if (bind(listenSock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
        error("ERROR on binding");

    listen(listenSock, 5);

    while (1) {
        // wait for a client
        clientSize = sizeof(clientAddr);
        connectSock = accept(listenSock, (struct sockaddr *)&clientAddr, &clientSize);
        if (connectSock < 0) error("ERROR on accept");

        pid_t pid = fork();
        if (pid < 0) { perror("fork"); close(connectSock); continue; }

        if (pid == 0) {
            // child handles this client
            memset(hsBuf, 0, sizeof(hsBuf));
            int n = recv(connectSock, hsBuf, sizeof(hsBuf) - 1, 0);
            if (n <= 0 || strcmp(hsBuf, "ENC") != 0) {
                sendAll(connectSock, "REJECT", 6);
                close(connectSock);
                exit(1);
            }
            sendAll(connectSock, "OK", 2);

            int netMsgLen = 0, netKeyLen = 0;
            recvAll(connectSock, (char*)&netMsgLen, sizeof(netMsgLen));
            recvAll(connectSock, (char*)&netKeyLen, sizeof(netKeyLen));
            int msgLen = ntohl(netMsgLen);
            int keyLen = ntohl(netKeyLen);

            if (keyLen < msgLen || msgLen < 0 || keyLen < 0 || msgLen > 150000 || keyLen > 150000) {
                close(connectSock);
                exit(1);
            }

            char *msg = (char*)malloc(msgLen + 1);
            char *key = (char*)malloc(keyLen + 1);
            if (!msg || !key) { fprintf(stderr, "ERROR: out of memory\n"); close(connectSock); exit(1); }

            recvAll(connectSock, msg, msgLen);
            recvAll(connectSock, key, keyLen);
            msg[msgLen] = '\0';
            key[keyLen] = '\0';

            char *cipher = (char*)malloc(msgLen + 1);
            if (!cipher) { fprintf(stderr, "ERROR: out of memory\n"); free(msg); free(key); close(connectSock); exit(1); }

            // encrypt
            encrypt(msg, key, cipher);

            // send back
            sendAll(connectSock, cipher, msgLen);

            free(cipher);
            free(msg);
            free(key);
            close(connectSock);
            exit(0);
        }

        // parent closes its copy and goes back to accept()
        close(connectSock);
    }

    close(listenSock);
    return 0;
}

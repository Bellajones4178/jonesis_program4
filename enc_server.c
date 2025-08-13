#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

// pull exactly len bytes (recv() can short-read)
void recvAll(int fd, char *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) { perror("recv"); exit(1); }
        got += n;
    }
}

// shove all bytes out (send() can short-write)
void sendAll(int fd, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) { perror("send"); exit(1); }
        sent += n;
    }
}

int main(int argc, char *argv[]) {
    int listenSock, connectSock, portNum;
    socklen_t clientSize;
    char hsBuf[16];
    struct sockaddr_in servAddr, clientAddr;

    if (argc < 2) { fprintf(stderr, "USAGE: %s port\n", argv[0]); exit(1); }

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
        if (connectSock < 0) error("ERROR on accept"

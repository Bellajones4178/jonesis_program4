#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

// turn a char into a number
int charToNum(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    } else if (c == ' ') {
        return 26;
    }
    return -1; 
}

// turn a number back into a char 
char numToChar(int n) {
    if (n >= 0 && n < 26) {
        return 'A' + n;
    } else if (n == 26) {
        return ' ';
    }
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

// take the encrypted message + key, reverse to give me the original text back
void decrypt(const char *cipherTxt, const char *keyTxt, char *plainTxt) {
    int i;
    for (i = 0; cipherTxt[i] != '\0'; i++) {
        int cNum = charToNum(cipherTxt[i]);
        int kNum = charToNum(keyTxt[i]);
        int pNum = cNum - kNum;
        if (pNum < 0) {
            pNum += 27; 
        }
        plainTxt[i] = numToChar(pNum);
    }
    plainTxt[i] = '\0';
}

// bail with an error
void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[]) {
    int listenSock, connectSock, portNum;
    socklen_t clientSize;
    char buffer[150000]; 
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
        if (connectSock < 0) error("ERROR on accept");

        memset(buffer, '\0', sizeof(buffer));
        recv(connectSock, buffer, sizeof(buffer) - 1, 0);
        if (strcmp(buffer, "ENC") != 0) {
            send(connectSock, "REJECT", 6, 0);
            close(connectSock);
            continue;
        }
        send(connectSock, "OK", 2, 0);

        memset(buffer, '\0', sizeof(buffer));
        recv(connectSock, buffer, sizeof(buffer) - 1, 0);
        char msg[150000];
        strcpy(msg, buffer);

        // get key
        memset(buffer, '\0', sizeof(buffer));
        recv(connectSock, buffer, sizeof(buffer) - 1, 0);
        char key[150000];
        strcpy(key, buffer);

        // encrypt it
        char cipher[150000];
        encrypt(msg, key, cipher);

        // send back encrypted text
        send(connectSock, cipher, strlen(cipher), 0);

        close(connectSock);
    }

    close(listenSock);
    return 0;
}
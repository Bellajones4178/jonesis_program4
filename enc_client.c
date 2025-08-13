#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

// read a file into a string
void readFile(char *filename, char *buf) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { fprintf(stderr, "Error: cannot open %s\n", filename); exit(1); }
    if (!fgets(buf, 150000, fp)) { buf[0] = '\0'; }
    buf[strcspn(buf, "\n")] = '\0';
    fclose(fp);
}

// check text only has A-Z or space
void validateText(const char *txt) {
    for (int i = 0; txt[i] != '\0'; i++) {
        if ((txt[i] < 'A' || txt[i] > 'Z') && txt[i] != ' ') {
            fprintf(stderr, "enc_client error: input contains bad characters\n");
            exit(1);
        }
    }
}

// shove all bytes out the door (send() can short-write)
void sendAll(int sockFD, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(sockFD, buf + sent, len - sent, 0);
        if (n < 0) { perror("send"); exit(1); }
        sent += n;
    }
}

// pull exactly len bytes (recv() can short-read)
void recvAll(int sockFD, char *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(sockFD, buf + got, len - got, 0);
        if (n <= 0) { perror("recv"); exit(1); }
        got += n;
    }
}

int main(int argc, char *argv[]) {
    int sockFD, portNum;
    struct sockaddr_in servAddr;
    struct hostent* serverInfo;
    char msg[150000], key[150000], buffer[16];

    if (argc < 4) {
        fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    // load plaintext/key, validate
    readFile(argv[1], msg);
    readFile(argv[2], key);

    validateText(msg);
    validateText(key);

    // Check for length
    if ((int)strlen(key) < (int)strlen(msg)) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    // set up server address
    memset((char*)&servAddr, '\0', sizeof(servAddr));
    portNum = atoi(argv[3]);
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(portNum);
    serverInfo = gethostbyname("localhost");
    if (!serverInfo) { fprintf(stderr, "Error: no such host\n"); exit(2); }
    memcpy((char*)&servAddr.sin_addr.s_addr, serverInfo->h_addr, serverInfo->h_length);

    // make socket
    sockFD = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFD < 0) { fprintf(stderr, "Error: opening socket\n"); exit(2); }

    // connect to server
    if (connect(sockFD, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portNum);
        exit(2);
    }

    // say who we are, expect "OK" back
    sendAll(sockFD, "ENC", 3);
    memset(buffer, 0, sizeof(buffer));
    int n = recv(sockFD, buffer, sizeof(buffer)-1, 0);
    if (n <= 0 || strcmp(buffer, "OK") != 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portNum);
        close(sockFD);
        exit(2);
    }

    // send lengths first so server knows what’s coming
    int msgLen = (int)strlen(msg);
    int keyLen = (int)strlen(key);
    int netMsgLen = htonl(msgLen);
    int netKeyLen = htonl(keyLen);
    sendAll(sockFD, (char*)&netMsgLen, sizeof(netMsgLen));
    sendAll(sockFD, (char*)&netKeyLen, sizeof(netKeyLen));

    // now send the actual text blobs
    sendAll(sockFD, msg, msgLen);
    sendAll(sockFD, key, keyLen);

    // get back the ciphertext (same length as plaintext)
    char *cipher = (char*)malloc(msgLen + 1);
    if (!cipher) { fprintf(stderr, "Error: out of memory\n"); close(sockFD); exit(1); }
    recvAll(sockFD, cipher, msgLen);
    cipher[msgLen] = '\0';

    // print to stdout (with newline per assignment)
    printf("%s\n", cipher);

    free(cipher);
    close(sockFD);
    return 0;
}

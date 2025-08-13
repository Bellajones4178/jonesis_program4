#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

// load file into buffer
char* readFile(const char *fname, int *outLen) {
    FILE *fp = fopen(fname, "r");
    if (!fp) { perror("fopen"); exit(1); }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);
    char *buf = malloc(size);
    if (!buf) { fprintf(stderr, "ERROR: out of memory\n"); exit(1); }
    size_t r = fread(buf, 1, size, fp);
    fclose(fp);
    if (r > 0 && buf[r - 1] == '\n') r--;
    buf[r] = '\0';
    *outLen = r;
    return buf;
}

int main(int argc, char *argv[]) {
    if (argc < 4) { fprintf(stderr, "USAGE: %s ciphertext key port\n", argv[0]); exit(1); }

    int cipherLen = 0, keyLen = 0;
    char *cipher = readFile(argv[1], &cipherLen);
    char *key = readFile(argv[2], &keyLen);
    if (keyLen < cipherLen) {
        fprintf(stderr, "ERROR: key too short\n");
        free(cipher);
        free(key);
        exit(1);
    }

    int sockfd;
    struct sockaddr_in servAddr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("ERROR opening socket");

    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(atoi(argv[3]));
    servAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0)
        error("ERROR connecting");

    sendAll(sockfd, "DEC", 3);
    char resp[3] = {0};
    recvAll(sockfd, resp, 2);
    if (strcmp(resp, "OK") != 0) {
        fprintf(stderr, "ERROR: server rejected connection\n");
        close(sockfd);
        free(cipher);
        free(key);
        exit(1);
    }

    int netCipherLen = htonl(cipherLen);
    int netKeyLen = htonl(keyLen);
    sendAll(sockfd, (char*)&netCipherLen, sizeof(netCipherLen));
    sendAll(sockfd, (char*)&netKeyLen, sizeof(netKeyLen));

    sendAll(sockfd, cipher, cipherLen);
    sendAll(sockfd, key, keyLen);

    char *plain = malloc(cipherLen + 1);
    if (!plain) { fprintf(stderr, "ERROR: out of memory\n"); close(sockfd); free(cipher); free(key); exit(1); }
    recvAll(sockfd, plain, cipherLen);
    plain[cipherLen] = '\0';

    printf("%s\n", plain);

    free(cipher);
    free(key);
    free(plain);
    close(sockfd);
    return 0;
}

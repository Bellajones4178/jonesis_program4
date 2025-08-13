#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

// read a file into a string (strip newline)
void readFile(char *filename, char *buf) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { fprintf(stderr, "Error: cannot open %s\n", filename); exit(1); }
    fgets(buf, 150000, fp);
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

int main(int argc, char *argv[]) {
    int sockFD, portNum;
    struct sockaddr_in servAddr;
    struct hostent* serverInfo;
    char msg[150000], key[150000], buffer[150000];

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
    if (strlen(key) < strlen(msg)) {
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

    send(sockFD, "ENC", 3, 0);
    memset(buffer, '\0', sizeof(buffer));
    recv(sockFD, buffer, sizeof(buffer) - 1, 0);
    if (strcmp(buffer, "OK") != 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portNum);
        close(sockFD);
        exit(2);
    }

    send(sockFD, msg, strlen(msg), 0);
    send(sockFD, key, strlen(key), 0);
    memset(buffer, '\0', sizeof(buffer));
    recv(sockFD, buffer, sizeof(buffer) - 1, 0);
    printf("%s\n", buffer);

    close(sockFD);
    return 0;
}

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
        if (connectSock < 0) error("ERROR on accept");

        // handshake: must be ENC or we bounce
        memset(hsBuf, 0, sizeof(hsBuf));
        int n = recv(connectSock, hsBuf, sizeof(hsBuf)-1, 0);
        if (n <= 0 || strcmp(hsBuf, "ENC") != 0) {
            sendAll(connectSock, "REJECT", 6);
            close(connectSock);
            continue;
        }
        sendAll(connectSock, "OK", 2);

        // lengths first so we know how much to read
        int netMsgLen = 0, netKeyLen = 0;
        recvAll(connectSock, (char*)&netMsgLen, sizeof(netMsgLen));
        recvAll(connectSock, (char*)&netKeyLen, sizeof(netKeyLen));
        int msgLen = ntohl(netMsgLen);
        int keyLen = ntohl(netKeyLen);

        if (keyLen < msgLen || msgLen < 0 || keyLen < 0 || msgLen > 150000 || keyLen > 150000) {
            // basic sanity; client should have caught short key already
            close(connectSock);
            continue;
        }

        // read the actual data blobs
        char *msg = (char*)malloc(msgLen + 1);
        char *key = (char*)malloc(keyLen + 1);
        if (!msg || !key) { fprintf(stderr, "ERROR: out of memory\n"); close(connectSock); exit(1); }

        recvAll(connectSock, msg, msgLen);
        recvAll(connectSock, key, keyLen);
        msg[msgLen] = '\0';
        key[keyLen] = '\0';

        // encrypt it
        char *cipher = (char*)malloc(msgLen + 1);
        if (!cipher) { fprintf(stderr, "ERROR: out of memory\n"); free(msg); free(key); close(connectSock); exit(1); }
        encrypt(msg, key, cipher);

        // send back encrypted text (exactly msgLen bytes)
        sendAll(connectSock, cipher, msgLen);

        free(cipher);
        free(msg);
        free(key);
        close(connectSock);
    }

    close(listenSock);
    return 0;
}
How to build & test fast
bash
Copy
Edit
gcc --std=gnu99 -o enc_server enc_server.c
gcc --std=gnu99 -o enc_client enc_client.c

./enc_server 57171 &
./keygen 1024 > mykey
./enc_client plaintext1 mykey 57171 > ciphertext1
wc -c plaintext1 ciphertext1   # should match (plus newline in files)
cat ciphertext1
This protocol change (send lengths first, then exact bytes; and loop for send/recv) is what fixes the grader’s timeout and “empty ciphertext” issues. After this, you can clone the same pattern for dec_server/dec_client (swap in your decrypt() and change the handshake to "DEC"), then add fork() to the servers to satisfy the concurrency tests.









Ask ChatGPT
You said:
No compileall or Makefile found - running default gcc commands
enc_server.c: In function ‘main’:
enc_server.c:91:53: error: expected ‘)’ at end of input
   91 |         if (connectSock < 0) error("ERROR on accept"
      |                                   ~                 ^
      |                                                     )
enc_server.c:91:9: error: expected declaration or statement at end of input
   91 |         if (connectSock < 0) error("ERROR on accept"
      |         ^~
enc_server.c:91:9: error: expected declaration or statement at end of input


0 pids:  set()
0 calls:  set()


0 pids:  set()
0 calls:  set()


ChatGPT said:
You’ve got a tiny syntax typo: this line is missing a closing ):

c
Copy
Edit
if (connectSock < 0) error("ERROR on accept"
…and because of that, the rest of the braces never close, so the compiler yells about “end of input”.

Here’s a clean, fixed enc_server.c you can paste over yours (same tone + length-prefixed protocol + reliable send/recv). I double-checked all parentheses/braces:

c
Copy
Edit
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

// pull exactly len bytes 
void recvAll(int fd, char *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) { perror("recv"); exit(1); }
        got += n;
    }
}

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
        if (connectSock < 0) error("ERROR on accept");

        memset(hsBuf, 0, sizeof(hsBuf));
        int n = recv(connectSock, hsBuf, sizeof(hsBuf) - 1, 0);
        if (n <= 0 || strcmp(hsBuf, "ENC") != 0) {
            sendAll(connectSock, "REJECT", 6);
            close(connectSock);
            continue;
        }
        sendAll(connectSock, "OK", 2);

        int netMsgLen = 0, netKeyLen = 0;
        recvAll(connectSock, (char*)&netMsgLen, sizeof(netMsgLen));
        recvAll(connectSock, (char*)&netKeyLen, sizeof(netKeyLen));
        int msgLen = ntohl(netMsgLen);
        int keyLen = ntohl(netKeyLen);

        if (keyLen < msgLen || msgLen < 0 || keyLen < 0 || msgLen > 150000 || keyLen > 150000) {
            
            close(connectSock);
            continue;
        }

        char *msg = (char*)malloc(msgLen + 1);
        char *key = (char*)malloc(keyLen + 1);
        if (!msg || !key) { fprintf(stderr, "ERROR: out of memory\n"); close(connectSock); exit(1); }

        recvAll(connectSock, msg, msgLen);
        recvAll(connectSock, key, keyLen);
        msg[msgLen] = '\0';
        key[keyLen] = '\0';

        // encrypt
        char *cipher = (char*)malloc(msgLen + 1);
        if (!cipher) { fprintf(stderr, "ERROR: out of memory\n"); free(msg); free(key); close(connectSock); exit(1); }
        encrypt(msg, key, cipher);

        // send back 
        sendAll(connectSock, cipher, msgLen);

        free(cipher);
        free(msg);
        free(key);
        close(connectSock);
    }

    close(listenSock);
    return 0;
}

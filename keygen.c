#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char numToChar(int n) {
    if (n >= 0 && n < 26) {
        return 'A' + n;
    } else if (n == 26) {
        return ' ';
    }
    return '?'; 
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        return 1;
    }

    char *endptr;
    long keyLength = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || keyLength <= 0) {
        fprintf(stderr, "Error: keylength needs to be a positive integer\n");
        return 1;
    }

    srand(time(NULL));

    for (long i = 0; i < keyLength; i++) {
        int randIndex = rand() % 27; 
        char c = numToChar(randIndex);
        putchar(c);
    }

    putchar('\n');
    return 0;
}


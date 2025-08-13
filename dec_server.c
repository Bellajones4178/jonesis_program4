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

int main(void) {
    // temp main for testing — remove later in server files
    return 0;
}

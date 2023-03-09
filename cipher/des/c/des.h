#ifndef DES_H
#define DES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef uint8_t BYTE;
typedef uint32_t WORD;
typedef uint64_t DWORD;
typedef enum {
    ENC,
    DEC
} operation;
typedef enum {
    ECB,
    CBC,
    OFB,
    CFB,
    CTR
} mode;

#define ROTL(x,n) (((x << n) & 0x0fffffff) | ((x >> 28 - n) & 0x0fffffff))
#define ROTR(x,n) (((x >> n) & 0x0fffffff) | ((x << 28 - n) & 0x0fffffff))
#define combine(l,r) (((l & 0xfffffff) << 28) | r)

const BYTE IPbox[64] = {
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
};

const BYTE Ebox[48] = {
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
};

const BYTE SBoxes[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },

    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },

    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },

    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },

    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },

    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },

    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },

    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

const BYTE PBox[32] = {
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

const BYTE FPbox[64] = {
    40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25
};

const BYTE permuted_choice_1[56] = {
    57,49,41,33,25,17,9,1,
    58,50,42,34,26,18,10,2,
    59,51,43,35,27,19,11,3,
    60,52,44,36,63,55,47,39,
    31,23,15,7,62,54,46,38,
    30,22,14,6,61,53,45,37,
    29,21,13,5,28,20,12,4
};

const BYTE permuted_choice_2[48] = {
    14,17,11,24,1,5,3,28,
    15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,
    34,53,46,42,50,36,29,32
};

const BYTE right_shifts[16] = { 0,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

const BYTE left_shifts[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

struct desKey {
    DWORD key;
    DWORD tKey;
    DWORD left;
    DWORD right;
    DWORD keys[16];
};

struct desPlain {
    DWORD plain;
    DWORD tPlain;
    DWORD ftPlain;
    WORD fPlain;
    WORD left;
    WORD tLeft;
    WORD tRight;
    WORD right;
};

void initDESKey(struct desKey *key, DWORD kVal, operation op) {
    key->key = kVal;
    key->tKey = 0;

    // permuted choice 1
    for(int i = 0; i < 56; i++) {
        key->tKey |= ((key->key >> 64 - permuted_choice_1[i]) & 1) << 55 - i;
    }

    // key splitting
    key->left = key->tKey >> 28;
    key->right = key->tKey & 0xfffffff;

    // key generation
    for(int i = 0; i < 16; i++) {
        // rotation
        switch(op) {
            case ENC:   key->left = ROTL(key->left,left_shifts[i]);
                        key->right = ROTL(key->right,left_shifts[i]);
                        break;
            case DEC:   key->left = ROTR(key->left,right_shifts[i]);
                        key->right = ROTR(key->right,right_shifts[i]);
                        break;
        }
        key->tKey = combine(key->left,key->right);

        // permuted choice 2
        for(int k = 0; k < 48; k++) {
            key->keys[i] |= ((key->tKey >> 56 - permuted_choice_2[k]) & 1) << 47 - k;
        }
    }
}

static int row_calculation(int input) {
    input = input & 0x21;
    int row = ((input >> 4) & 2) + (input & 1);
    return row;
}

static int column_calculation(int input) {
    input = input & 0x1E;
    int column = (input >> 1) & 0xF;
    return column;
}

static unsigned int sbox(unsigned int input, int box) {
    return SBoxes[box][row_calculation(input)][column_calculation(input)];
}

void f(struct desPlain  *plain, DWORD key) {
    plain->tPlain = 0;
    plain->ftPlain = 0;
    plain->fPlain = 0;

    // expansion box
    for (int i = 0; i < 48; i++) {
        plain->tPlain |= ((DWORD)(plain->right >> 32 - Ebox[i]) & 1) << 47 - i;
    }

    // key addition
    plain->tPlain ^= key;

    // S-Box
    for (int i = 0; i < 8; i++) {
        BYTE input = (plain->tPlain >> 42 - 6 * i) & 0x3F;
        plain->ftPlain |= sbox(input, i) << 28 - 4 * i;
    }

    // pbox
    for (int i = 0; i < 32; i++) {
        plain->fPlain |= ((plain->ftPlain >> 32 - PBox[i]) & 1) << 31 - i;
    }
}

void operate(struct desPlain *plain, struct desKey *key) {
    plain->tPlain = 0;
    
    // IP
    for (int i = 0; i < 64; i++) {
        plain->tPlain |= ((plain->plain >> 64 - IPbox[i]) & 1) << 63 - i;
    }

    // Splitting
    plain->left = plain->tPlain >> 32;
    plain->right = plain->tPlain;

    for(int i = 0; i < 16; i++) {
        // f-function
        f(plain, key->keys[i]);

        plain->tRight = plain->fPlain;
        plain->tLeft = plain->left ^ plain->tRight;

        plain->left = plain->right;
        plain->right = plain->tLeft;
    }

    plain->tPlain = ((DWORD) plain->right) << 32 | plain->left;
 
    plain->plain = 0;
    for (int i = 0; i < 64; i++) {
        plain->plain |= ((plain->tPlain >> 64 - FPbox[i]) & 1) << 63 - i;
    }
}

void operateFileECB(char *filename, struct desKey *key) {
    FILE *file = fopen(filename, "rb");
    FILE *fileout = fopen("encrypted", "wb");
    struct desPlain *plaintext = (struct desPlain *) malloc(sizeof(struct desPlain));

    while(fread(&plaintext->plain, sizeof(DWORD), 1, file) == 1) {
        operate(plaintext, key);
        fwrite(&plaintext->plain, sizeof(DWORD), 1 , fileout);
    }

    fclose(file);
    free(plaintext);
}

#endif

#ifndef SHA256_H
#define SHA256_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef uint8_t   BYTE;
typedef uint32_t  WORD;
typedef uint64_t  DWORD;

// rotate left/right
#define ROTL(x,n) ((x << n) | (x >> 32 - n))
#define ROTR(x,n) ((x >> n) | (x << 32 - n))

// shift left/right
#define SHL(x,n) (x << n)
#define SHR(x,n) (x >> n)

// functions
#define Ch(x,y,z) ((x & y) ^ (~x&z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

#define char_to_word(a,b,c,d) (WORD)(((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | ((d & 0xff)))

// Constants
const WORD K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256Round(WORD *H, WORD *message) {
    // words of message schedule
    WORD W[64] = {0};

    // temporary words
    WORD T1, T2;

    // working variables
    WORD a,b,c,d,e,f,g,h;

    // preparing message schedule
    for (int t = 0; t < 64; t++) {
        if (t < 16) {
            W[t] = message[t];
        }
        else {
            W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
        }
    }

    // initializing working variables
    a=H[0];
    b=H[1];
    c=H[2];
    d=H[3];
    e=H[4];
    f=H[5];
    g=H[6];
    h=H[7];

    // hash calculation
    for (int t = 0; t < 64; t++) {
        T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t];
        T2 = Sigma0(a) + Maj(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    
    // computing i-th intermediate hash value
    H[0] = a + H[0];
    H[1] = b + H[1];
    H[2] = c + H[2];
    H[3] = d + H[3];
    H[4] = e + H[4];
    H[5] = f + H[5];
    H[6] = g + H[6];
    H[7] = h + H[7];
}

WORD estimated_size(size_t size) {
    if (size <= 55) {
        return 64;
    }
    else {
        if (((size % 64) == 0) || ((size % 64) >= 56)) {
            return (size + 63) / 64 + 1;
        }
        return (size + 63) / 64;
    }
}

void convert(WORD* message, BYTE* buffer) {
    for (int i = 0; i < 64; i += 4) {
        message[i / 4] = char_to_word(buffer[i],buffer[i+1],buffer[i+2],buffer[i+3]);
    }
}

void finalise(WORD *H, BYTE *buffer, size_t read, DWORD bits) {
    WORD message[16];
    if ((read >= 56) && (read != 100)) {
        if (read == 64) {
            convert(message, buffer);
            sha256Round(H, message);
            read = 0;
        }
        else {
            buffer[read] = 0x80;
            convert(message, buffer);
            sha256Round(H, message);
            read = 100;
        }
        memset(buffer, 0, sizeof(BYTE) * 64);
        finalise(H,buffer,read,bits);
    }
    else {
        if (read != 100) {
            buffer[read] = 0x80;
        }
        for (int k = 0; k < 64; k++) {
            if(k>=56) {
                buffer[k] = bits >> (56 - (k-56) * 8);
            }
            else if ((k>read) && (k < 56) && (k != read)) {
                buffer[k] = 0;
            }
        }
        convert(message, buffer);
        sha256Round(H, message);
    }
}

void sha256FromFile(char *filename) {
    FILE *file;
    
    // INITIAL HASH VALUES
    WORD H[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    BYTE buffer[64];
    DWORD bits = 0;
    size_t read,size;

    clock_t start = clock();

    file = fopen(filename,"rb");

    // extracting file size
    fseek(file, 0L, SEEK_END);
    size = ftell(file);
    bits = size * 8;
    fseek(file, 0L, SEEK_SET);

    // calculating estimated size
    size_t est_size = estimated_size(size);

    for(int i = 0; (i+64) < size; i+=64) {
        WORD message[16];

        read = fread(buffer, 1, sizeof(buffer), file);
        convert(message, buffer);
        sha256Round(H, message);
        memset(buffer, 0, sizeof(BYTE) * 64);
    }
    
    read = fread(buffer, 1, sizeof(buffer), file);
    finalise(H, buffer, read, bits);

    printf("%02x%02x%02x%02x%02x%02x%02x%02x\n", H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);
}

#endif

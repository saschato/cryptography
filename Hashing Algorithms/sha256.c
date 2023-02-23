#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef uint8_t   BYTE;
typedef uint32_t  WORD;
typedef uint64_t  DWORD;

// rotate left/right
#define ROTL(x,n) (x >> n) | (x << (32 - n))
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

// messageblock structure
struct message_block {
    WORD m[16];
    DWORD length;
};

void sha_256(struct message_block message) {    
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

    // words of message schedule
    WORD W[64] = {0};

    // temporary words
    WORD T1, T2;

    // working variables
    WORD a,b,c,d,e,f,g,h;

    // preparing message schedule
    for (int t = 0; t < 64; t++) {
        if (t < 16) {
            W[t] = message.m[t];
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

    printf("%02x%02x%02x%02x%02x%02x%02x%02x\n",H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);
}

// currently only < 448 bits supported
// and only 8 Bit characters
// and string length mod 4 == 0
struct message_block convert(char *string) {
    struct message_block message;

    // setting values
    message.length = strlen(string);
    
    for (int i = 0; i < 15; i++) {
        if (i < (message.length / 4)) {
            message.m[i] = 0;
            for (int j = 0; j < 4; j++) {
                message.m[i] |= (string[i*4+j] & 0xff) << (24-j*8);
            }
        }
        else if (i == (message.length / 4)) {
            message.m[i] = 0x80000000;
        }
        else {
            message.m[i] = 0;
        }
    }

    // message length
    message.m[15] = message.length*8;
    
    return message;
}

int main() {
    sha_256(convert("password"));

    return 0;
}

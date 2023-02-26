#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
//#include "MoD.h"
#include "structures.h"

// reduction polynomial
#define P 0x11B

// Round Constants
const BYTE RC[10] = {0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x1B,0x36};

// SBox
const BYTE SBox[16][16] = {
	{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
	{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
	{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
	{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
	{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
	{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
	{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
	{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
	{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
	{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
	{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
	{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
	{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
	{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
	{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
	{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

// padding
void pad(struct aesState *state) {

}

void unpad(struct aesState *state) {

}

// initializing state
struct aesState *initState(struct aesState *state) {
    state = (struct aesState *) malloc(sizeof(struct aesState));
    return state;
}

// initializing subkeys
struct aesKey *initAESKey(char *keyStr) {
    size_t size = strlen(keyStr);
    if ((size != 32) && (size != 48) && (size != 64)) {
        return NULL;
    }

    // allocating memory for aes Key structure
    struct aesKey *key = (struct aesKey *) malloc(sizeof(struct aesKey) + size * sizeof(char));
    
    // copying key to structure
    strcpy(key->keyStr, keyStr);

    key->kSize = size*4;
    key->keyStr_size = size;
    
    if(size == 32) {
        key->nKeys = 11;
    }
    else if(size == 48) {
        key->nKeys = 13;
    }
    else {
        key->nKeys = 15;
    }

    // creating subkey structures
    for (int i = 0; i < key->nKeys; i++) {
        struct aesSubKey k;
        key->subkeys[i] = k;
    }

    // converting keyStr to subkey byte array
    int j = 0;
    for(size_t i = 0; i < size; i+=2) {
        char *ptr;
        char k[2];
        strncpy(k,keyStr+i,2);
        key->subkeys[j].bytes[(i/2) % 16] = strtol(k,&ptr,16);
        if(i == 30) {
            j = 1;
        }
    }

    return key;
}

// SFP Functions
BYTE sbox(BYTE byte) {
	return SBox[byte >> 4][byte & 0xf];
}

BYTE *g(BYTE bytes[], BYTE round) {
    BYTE t1 = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = bytes[2];
    bytes[2] = bytes[3];
    bytes[3] = t1;

    for (int i = 0; i < 4; i++) {
        bytes[i] = sbox(bytes[i]);
    }

    bytes[0] ^= RC[round];

    return bytes;
}

// SFPs
struct aesKey *SFP(struct aesKey *key) {
    if((key->kSize) == 128) {
        for(BYTE k = 1; k < 11; k++) {
            BYTE bytes[4];
            strncpy(bytes, key->subkeys[k-1].bytes+12, 4);
            BYTE * gBytes = g(bytes,k-1);
            key->subkeys[k].bytes[0] = key->subkeys[k-1].bytes[0]^gBytes[0];
            key->subkeys[k].bytes[1] = key->subkeys[k-1].bytes[1]^gBytes[1];
            key->subkeys[k].bytes[2] = key->subkeys[k-1].bytes[2]^gBytes[2];
            key->subkeys[k].bytes[3] = key->subkeys[k-1].bytes[3]^gBytes[3];
            key->subkeys[k].bytes[4] = key->subkeys[k-1].bytes[4]^key->subkeys[k].bytes[0];
            key->subkeys[k].bytes[5] = key->subkeys[k-1].bytes[5]^key->subkeys[k].bytes[1];
            key->subkeys[k].bytes[6] = key->subkeys[k-1].bytes[6]^key->subkeys[k].bytes[2];
            key->subkeys[k].bytes[7] = key->subkeys[k-1].bytes[7]^key->subkeys[k].bytes[3];
            key->subkeys[k].bytes[8] = key->subkeys[k-1].bytes[8]^key->subkeys[k].bytes[4];
            key->subkeys[k].bytes[9] = key->subkeys[k-1].bytes[9]^key->subkeys[k].bytes[5];
            key->subkeys[k].bytes[10] = key->subkeys[k-1].bytes[10]^key->subkeys[k].bytes[6];
            key->subkeys[k].bytes[11] = key->subkeys[k-1].bytes[11]^key->subkeys[k].bytes[7];
            key->subkeys[k].bytes[12] = key->subkeys[k-1].bytes[12]^key->subkeys[k].bytes[8];
            key->subkeys[k].bytes[13] = key->subkeys[k-1].bytes[13]^key->subkeys[k].bytes[9];
            key->subkeys[k].bytes[14] = key->subkeys[k-1].bytes[14]^key->subkeys[k].bytes[10];
            key->subkeys[k].bytes[15] = key->subkeys[k-1].bytes[15]^key->subkeys[k].bytes[11];
        }
    }
    return key;
}

// functions
struct aesState* ShiftRows(struct aesState *state) {
    BYTE t1;
    
    t1 = state->bytes[1];
    state->bytes[1] = state->bytes[5];
    state->bytes[5] = state->bytes[9];
    state->bytes[9] = state->bytes[13];
    state->bytes[13] = t1;

    t1 = state->bytes[2];
    state->bytes[2] = state->bytes[10];
    state->bytes[10] = t1;
    t1 = state->bytes[6];
    state->bytes[6] = state->bytes[14];
    state->bytes[14] = t1;

    t1 = state->bytes[3];
    state->bytes[3] = state->bytes[15];
    state->bytes[15] = state->bytes[11];
    state->bytes[11] = state->bytes[7];
    state->bytes[7] = t1;    

    return state;
}

BYTE reduction(BYTE multiplier, uint16_t temp) {
    if (multiplier == 2) {
        temp <<= 1;
    }
    else if (multiplier == 3) {
        temp = (temp << 1) ^ temp;
    }

    while((temp & 0xff00) != 0) {
        temp^=(P<<(32-9-__builtin_clz(temp)));
    }
    
    return temp;
}

struct aesState *MixColumns(struct aesState *state){
    BYTE a,b,c,d;

    a = reduction(2,state->bytes[0])^reduction(3,state->bytes[1])^state->bytes[2]^state->bytes[3];
    b = state->bytes[0]^reduction(2,state->bytes[1])^reduction(3,state->bytes[2])^state->bytes[3];
    c = state->bytes[0]^state->bytes[1]^reduction(2,state->bytes[2])^reduction(3,state->bytes[3]);
    d = reduction(3,state->bytes[0])^state->bytes[1]^state->bytes[2]^reduction(2,state->bytes[3]);

    state->bytes[0] = a;
    state->bytes[1] = b;
    state->bytes[2] = c;
    state->bytes[3] = d;

    a = reduction(2,state->bytes[4])^reduction(3,state->bytes[5])^state->bytes[6]^state->bytes[7];
    b = state->bytes[4]^reduction(2,state->bytes[5])^reduction(3,state->bytes[6])^state->bytes[7];
    c = state->bytes[4]^state->bytes[5]^reduction(2,state->bytes[6])^reduction(3,state->bytes[7]);
    d = reduction(3,state->bytes[4])^state->bytes[5]^state->bytes[6]^reduction(2,state->bytes[7]);

    state->bytes[4] = a;
    state->bytes[5] = b;
    state->bytes[6] = c;
    state->bytes[7] = d;

    a = reduction(2,state->bytes[8])^reduction(3,state->bytes[9])^state->bytes[10]^state->bytes[11];
    b = state->bytes[8]^reduction(2,state->bytes[9])^reduction(3,state->bytes[10])^state->bytes[11];
    c = state->bytes[8]^state->bytes[9]^reduction(2,state->bytes[10])^reduction(3,state->bytes[11]);
    d = reduction(3,state->bytes[8])^state->bytes[9]^state->bytes[10]^reduction(2,state->bytes[11]);

    state->bytes[8] = a;
    state->bytes[9] = b;
    state->bytes[10] = c;
    state->bytes[11] = d;

    a = reduction(2,state->bytes[12])^reduction(3,state->bytes[13])^state->bytes[14]^state->bytes[15];
    b = state->bytes[12]^reduction(2,state->bytes[13])^reduction(3,state->bytes[14])^state->bytes[15];
    c = state->bytes[12]^state->bytes[13]^reduction(2,state->bytes[14])^reduction(3,state->bytes[15]);
    d = reduction(3,state->bytes[12])^state->bytes[13]^state->bytes[14]^reduction(2,state->bytes[15]);

    state->bytes[12] = a;
    state->bytes[13] = b;
    state->bytes[14] = c;
    state->bytes[15] = d;

    return state;
}

// main encryption function
void encrypt(struct aesState *state, struct aesKey *key) {
    // initial key XOR
    for (int i = 0; i < 16; i++) {
        state->bytes[i] ^= key->subkeys[0].bytes[i];
    }

    // main
    for (int i = 1; i < key->nKeys; i++) {
        // ByteSub
        for(int k = 0; k < 16; k++) {
            state->bytes[k] = sbox(state->bytes[k]);
        }

        // Shift Rows
        state = ShiftRows(state);

        // Mix-Column
        if (i != (key->nKeys - 1)) {
            MixColumns(state);
        }

        // Key Addition
        for(int k = 0; k < 16; k++) {
            state->bytes[k] ^= key->subkeys[i].bytes[k];
        }
    }
}

int encryptFile(char *filename, char *mode, char *keyStr) {    
    // initializing
    struct aesState *state = initState(state);;
    struct aesKey *key = initAESKey(keyStr);
    
    if(key == NULL) {
        return 1;
    }

    // computing necessary subkeys
    key = SFP(key);

    // file handling
    FILE *file, *out;
    file = fopen(filename, "rb");
    out = fopen("encrypted","wb");

    while(fread(state->bytes, 1, 16, file) == 16) {
        encrypt(state,key);
        fwrite(state->bytes, 1, 16, out);
    }

    // closing files
    fclose(file);
    fclose(out);

    free(state);
    free(key);
}

#endif
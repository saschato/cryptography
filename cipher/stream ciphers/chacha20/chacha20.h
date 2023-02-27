#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define swap(x) (((x & 0xff) << 24u)|((x & 0xff00) << 8u)|((x & 0xff0000) >> 8u)|((x & 0xff000000) >> 24u))
#define ROTL(x,n) ((x << n) | (x >> 32 - n))

typedef uint8_t BYTE;
typedef uint32_t WORD;

struct chacha20State {
    WORD bCounter;
    WORD words[16];
    BYTE SBytes[64];
};

// strtol overflow -> strtoll
WORD strToWord(char *key) {
    char *ptr;
    char k[8];
    strncpy(k, key, 8 * sizeof(BYTE));
    return strtoll(k, &ptr, 16);
}

struct chacha20State *initState(char *keyStr, char *nonceStr) {
    struct chacha20State *state = (struct chacha20State *) malloc(sizeof(struct chacha20State));

    // initializing block counter
    state->bCounter = 0;

    // defaults
    state->words[0] = 0x61707865;
    state->words[1] = 0x3320646e;
    state->words[2] = 0x79622d32;
    state->words[3] = 0x6b206574;

    // key
    for(int i = 4; i < 12; i++) {
        state->words[i] = swap(strToWord(keyStr+(i-4)*8));
    }

    // block counter
    state->words[12] = state->bCounter;

    // nonce
    for (int i = 13; i < 16; i++) {
        state->words[i] = swap(strToWord(nonceStr+(i-13)*8));
    }

    return state;
}

BYTE *initOutput() {
    BYTE *keystream = (BYTE *) malloc(64 * sizeof(BYTE));
    return keystream;
}

void quarterRound(WORD *state, int a, int b, int c, int d) {
    state[a] =  state[a] + state[b];
	state[d] ^= state[a];
	state[d] = ROTL(state[d],16);

	state[c] = state[c] + state[d];
	state[b] ^= state[c];
	state[b] = ROTL(state[b],12);

	state[a] =  state[a] + state[b];
	state[d] ^= state[a];
	state[d] = ROTL(state[d],8);

	state[c] = state[c] + state[d];
	state[b] ^= state[c];
	state[b] = ROTL(state[b],7);
}   

void generateChachaKeystream(struct chacha20State *state) {
    state->words[12] = state->bCounter;
    
    WORD *initialState = (WORD *) malloc(16*sizeof(WORD));
    memcpy(initialState, state->words, 16*sizeof(WORD));

    for (int i = 0; i < 10; i++) {
        quarterRound(initialState, 0, 4, 8, 12);
		quarterRound(initialState, 1, 5, 9, 13);
		quarterRound(initialState, 2, 6, 10, 14);
		quarterRound(initialState, 3, 7, 11, 15);
		quarterRound(initialState, 0, 5, 10, 15);
		quarterRound(initialState, 1, 6, 11, 12);
		quarterRound(initialState, 2, 7, 8, 13);
		quarterRound(initialState, 3, 4, 9, 14);
    }

    for(int i = 0; i < 16; i++) {
        initialState[i] += state->words[i];
    }

    // #TODO optimieren
    for(int i = 0; i < 64; i+=4) {
        // big - little endian conversion
        state->SBytes[i+3] = initialState[i/4] >> 24;
        state->SBytes[i+2] = (initialState[i/4] >> 16) & 0xff;
        state->SBytes[i+1] = (initialState[i/4] >> 8) & 0xff;
        state->SBytes[i] = initialState[i/4] & 0xff;
    }

    state->bCounter += 1;
    free(initialState);
}

void encdec(struct chacha20State *state, BYTE *buffer) {
    generateChachaKeystream(state);
    for(int i = 0; i < 64; i++) {
        buffer[i] ^= state->SBytes[i];
    }
}

#endif

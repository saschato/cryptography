# ChaCha20


This represents an implementation of the ChaCha20 stream cipher defined in [RFC-8439](https://datatracker.ietf.org/doc/html/rfc8439).

________________

### Initialization

At first we have to initialize the chacha20 state with it's start values. The state is has 16 words. The first 4 words are constants

```
state->words[0] = 0x61707865;
state->words[1] = 0x3320646e;
state->words[2] = 0x79622d32;
state->words[3] = 0x6b206574;
```

and the following 8 words represent the 256-Bit key splitted into 8 words. The LSB of the key is stored in the 5th word and so on. Because the key is given as a hexstring we have to convert it into 8 32 Bit unsigned integers before we can assign the to state words.

```
WORD strToWord(char *key) {
    char *ptr;
    char k[8];
    strncpy(k, key, 8 * sizeof(BYTE));
    return strtoll(k, &ptr, 16);
}

for(int i = 4; i < 12; i++) {
        state->words[i] = swap(strToWord(keyStr+(i-4)*8));
}
```

The states 13th word represents the block counter that is increased every encryption round.

The words 14-16 are the 96-Bit Nonce.

### Encryption/Decryption

Since ChaCha20 is a stream cipher the actual encryption/decryption is a xor of the plaintext and the keystream.

```
void encdec(struct chacha20State *state, BYTE *buffer) {
    generateChachaKeystream(state);
    for(int i = 0; i < 64; i++) {
        buffer[i] ^= state->SBytes[i]; // encrypting the buffer
    }
}
```

### Keystream Generation

The keystream is generated in the `function void generateChachaKeystream(struct chacha20State *state)`. 
In the first step the 13th word is tet to the current block count value followed by a copy of the initial state stored in the variable `WORD *initialState`. This is followed by 80 quarter round operating in 10 groups of 8 quarterrounds.

```
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
```

The last step of the keystream generation is to xor the initial state with the state after the quarterrounds. The result is the generated keystream.


#include <stdio.h>
#include <stdlib.h>
#include "chacha20.h"

int main(int argc, void **argv) {
    // state initialization                  |> 256 Bit key as hexstring                                        |> 96 Bit nonce
    struct chacha20State *state = initState("5cab66d519c304ed0b0180a9c023930c9d77f19f6b3a1af3aa602f7b1d9cfa9e","7731d1e5ee6d89c98364e394");

    // creating output buffer
    BYTE buffer[64];

    // file pointer
    FILE *file, *out;

    // opening the files
    file = fopen(argv[1], "rb");
    out = fopen(argv[2], "wb");

    // encrypting/decrypting 64 Byte blocks
    while(fread(buffer, 1, 64, file) != 0){
        encdec(state, buffer);
        fwrite(buffer, 1, 64, out);
    }

    // closing files
    fclose(file);
    fclose(out);

    return 0;
}

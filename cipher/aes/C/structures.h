#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <stdint.h>
#include <string.h>

typedef uint8_t   BYTE;
typedef uint32_t  WORD;
typedef uint64_t  DWORD;

// AES
// subkey structure
struct aesSubKey {
    BYTE bytes[16];
};

struct aesKey {
    BYTE kSize;
    BYTE nKeys;
    struct aesSubKey subkeys[15];
    BYTE keyStr_size;
    char keyStr[];
};

// AES state structure
struct aesState {
    BYTE bytes[16];
};

#endif

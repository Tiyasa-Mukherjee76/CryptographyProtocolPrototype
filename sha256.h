#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define SHA256_HASH_SIZE 32

// Function to compute SHA-256 hash
void sha256_hash(const uint8_t* data, uint32_t len, uint8_t* hash);

#endif

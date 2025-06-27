#ifndef DIFFIE_HELLMAN_H
#define DIFFIE_HELLMAN_H

#include <stdint.h>

// Function declarations for Diffie-Hellman key exchange
uint64_t dh_modular_pow(uint64_t base, uint64_t exp, uint64_t modulus);
uint64_t dh_generate_public_key(uint64_t prime, uint64_t generator, uint64_t private_key);
uint64_t dh_compute_shared_secret(uint64_t prime, uint64_t other_public, uint64_t private_key);

#endif

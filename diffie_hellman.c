#include "diffie_hellman.h"

// Optimized modular exponentiation using square-and-multiply algorithm
uint64_t dh_modular_pow(uint64_t base, uint64_t exp, uint64_t modulus) {
    uint64_t result = 1;
    base = base % modulus;
    while (exp > 0) {
        // If exponent is odd, multiply result with base
        if (exp & 1) { // Bitwise AND to check if odd
            result = (result * base) % modulus;
        }
        // Square the base
        base = (base * base) % modulus;
        exp >>= 1; // Right shift to divide exponent by 2
    }
    return result;
}

// Generate public key: g^private_key mod prime
uint64_t dh_generate_public_key(uint64_t prime, uint64_t generator, uint64_t private_key) {
    if (prime == 0 || generator == 0 || private_key == 0) return 0;
    return dh_modular_pow(generator, private_key, prime);
}

// Compute shared secret: other_public^private_key mod prime
uint64_t dh_compute_shared_secret(uint64_t prime, uint64_t other_public, uint64_t private_key) {
    if (prime == 0 || other_public == 0 || private_key == 0) return 0;
    return dh_modular_pow(other_public, private_key, prime);
}

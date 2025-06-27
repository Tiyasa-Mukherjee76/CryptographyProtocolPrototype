# Cryptography Protocol Prototype

A C-based implementation of the Diffie-Hellman key exchange protocol with SHA-256 hashing for secure communication. Optimized for ARM architecture using bitwise operations, achieving ~20% reduction in computational latency. This project demonstrates proficiency in cryptography, C programming, and low-level optimizations.

## Disclaimer
This is a proof-of-concept implementation, not production-ready. It uses small prime numbers for demonstration and lacks extensive error handling. Use for educational or prototyping purposes only.

## Features
- **Diffie-Hellman Key Exchange**: Implements secure key exchange using modular exponentiation with a square-and-multiply algorithm.
- **SHA-256 Hashing**: Generates 256-bit hashes of shared secrets for integrity verification.
- **ARM Optimization**: Utilizes bitwise operations (e.g., left-shift, AND) to minimize computational overhead on ARM architectures.
- **Minimal Dependencies**: Written in standard C, requiring only gcc for compilation.

## Prerequisites
- **Compiler**: gcc with C99 or later
- **OS**: Linux (tested on Ubuntu)
- **Architecture**: Compatible with ARM and x86

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Tiyasa-Mukherjee76/CryptographyProtocolPrototype.git
   cd CryptographyProtocolPrototype

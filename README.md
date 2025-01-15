# Montgomery Chaos Lattices

**Montgomery Chaos Lattices** is a Rust-based encryption and decryption library that leverages advanced lattice structures, Montgomery ladder techniques, chaotic sequences, and cryptographic primitives to provide a secure and efficient cipher. Designed with both performance and security in mind, this library offers a robust solution for applications requiring strong data confidentiality and integrity.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Generating a Chaos Key](#generating-a-chaos-key)
  - [Verifying a Chaos Key](#verifying-a-chaos-key)
  - [Encrypting a Message](#encrypting-a-message)
  - [Decrypting a Message](#decrypting-a-message)
- [Command-Line Interface](#command-line-interface)
- [Configuration](#configuration)
- [Examples](#examples)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

- **Lattice-Based Encryption**: Utilizes advanced lattice structures for robust encryption.
- **Montgomery Ladder Transformations**: Implements Montgomery ladder techniques for secure and efficient lattice row binding, enhancing resistance against side-channel attacks.
- **Chaotic Sequences**: Incorporates chaos-based algorithms to generate pseudorandom sequences, ensuring high entropy and unpredictability.
- **S-Box Substitution**: Implements substitution boxes (S-Boxes) for non-linear transformations, providing strong confusion properties.
- **Inverse S-Box**: Facilitates accurate decryption by reversing the S-Box transformations.
- **HMAC Integrity**: Ensures data integrity and authenticity using HMAC with SHA3-256.
- **Key Generation and Management**: Provides tools for generating and verifying secure chaos keys.
- **Command-Line Interface**: Easy-to-use CLI for performing encryption, decryption, key generation, and verification.
- **PEM-Like Formatting**: Supports PEM-like formats for keys and ciphertexts with standardized line breaks.

## Installation

### Prerequisites

- **Rust**: Ensure you have the Rust toolchain installed. If not, install it from [rustup.rs](https://rustup.rs/).

### Steps

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/montgomery-chaos-lattices.git
   cd montgomery-chaos-lattices
   ```

2. **Build the Project**

   ```bash
   cargo build --release
   ```

3. **Install the Executable**

   To install the executable system-wide:

   ```bash
   cargo install --path .
   ```

   This will place the `montgomery-chaos-lattices` binary in your `$PATH`.

## Usage

Montgomery Chaos Lattices provides a command-line interface (CLI) with the following commands:

- `gen`: Generate a chaos key.
- `verify`: Verify the integrity of a chaos key.
- `encrypt`: Encrypt a plaintext file.
- `decrypt`: Decrypt a ciphertext file.

### Generating a Chaos Key

Generate a chaos key with a specified bit size and save it to a file.

```bash
montgomery-chaos-lattices gen <bits> <output_file>
```

**Parameters:**

- `<bits>`: Size of the key in bits (must be a multiple of 64 and at least 64).
- `<output_file>`: Path to save the generated chaos key.

**Example:**

```bash
montgomery-chaos-lattices gen 256 chaos_key.pem
```

### Verifying a Chaos Key

Verify the integrity of an existing chaos key.

```bash
montgomery-chaos-lattices verify <bits> <input_file>
```

**Parameters:**

- `<bits>`: Size of the key in bits (must match the key's bit size).
- `<input_file>`: Path to the chaos key file to verify.

**Example:**

```bash
montgomery-chaos-lattices verify 256 chaos_key.pem
```

### Encrypting a Message

Encrypt a plaintext file using a chaos key.

```bash
montgomery-chaos-lattices encrypt <bits> <key_file> <plaintext_file> <ciphertext_file>
```

**Parameters:**

- `<bits>`: Size of the key in bits (must match the key's bit size).
- `<key_file>`: Path to the chaos key file.
- `<plaintext_file>`: Path to the plaintext file to encrypt.
- `<ciphertext_file>`: Path to save the encrypted ciphertext.

**Example:**

```bash
montgomery-chaos-lattices encrypt 256 chaos_key.pem message.txt ciphertext.pem
```

### Decrypting a Message

Decrypt a ciphertext file using a chaos key.

```bash
montgomery-chaos-lattices decrypt <bits> <key_file> <ciphertext_file> <decrypted_file>
```

**Parameters:**

- `<bits>`: Size of the key in bits (must match the key's bit size).
- `<key_file>`: Path to the chaos key file.
- `<ciphertext_file>`: Path to the ciphertext file to decrypt.
- `<decrypted_file>`: Path to save the decrypted plaintext.

**Example:**

```bash
montgomery-chaos-lattices decrypt 256 chaos_key.pem ciphertext.pem decrypted_message.txt
```

## Command-Line Interface

Here’s a summary of the available commands and their usage:

```bash
montgomery-chaos-lattices <command> [arguments]

Commands:
  gen <bits> <output_file>                       Generate a chaos key.
  verify <bits> <input_file>                      Verify a chaos key.
  encrypt <bits> <key_file> <plaintext> <cipher> Encrypt a plaintext file.
  decrypt <bits> <key_file> <cipher> <decrypted>  Decrypt a ciphertext file.
```

### Help

For detailed help on each command, use the `--help` flag:

```bash
montgomery-chaos-lattices --help
montgomery-chaos-lattices gen --help
montgomery-chaos-lattices verify --help
montgomery-chaos-lattices encrypt --help
montgomery-chaos-lattices decrypt --help
```

## Configuration

Montgomery Chaos Lattices allows customization through various parameters:

- **Key Size (`bits`)**: Determines the strength of the chaos key. Must be a multiple of 64 and at least 64 bits.
- **Small Prime Limit**: Used during key generation to sieve small primes. Default is set to 10,000.
- **Prime Bits**: Number of bits for prime generation in lattice points. Default is 256 bits.
- **Miller-Rabin Rounds**: Number of rounds for primality testing. Default is 40 for enhanced security.
- **Lattice Dimensions and Size**: Configurable dimensions and size of the lattice structure, influencing the complexity and security of the cipher.

These parameters can be adjusted by modifying the source code or through additional configuration files if implemented in future updates.

## Examples

### 1. Generating a 256-bit Chaos Key

```bash
montgomery-chaos-lattices gen 256 chaos_key.pem
```

**Output:**

```
Chaos key successfully saved to chaos_key.pem
```

### 2. Verifying the Generated Chaos Key

```bash
montgomery-chaos-lattices verify 256 chaos_key.pem
```

**Output:**

```
Chaos key verification successful. HMAC is valid.
```

### 3. Encrypting a Plaintext File

Assume you have a plaintext file named `secret.txt`.

```bash
montgomery-chaos-lattices encrypt 256 chaos_key.pem secret.txt secret_encrypted.pem
```

**Output:**

```
Encryption successful. Ciphertext saved to secret_encrypted.pem
```

### 4. Decrypting the Ciphertext File

```bash
montgomery-chaos-lattices decrypt 256 chaos_key.pem secret_encrypted.pem secret_decrypted.txt
```

**Output:**

```
Decryption successful. Plaintext saved to secret_decrypted.txt
```

After decryption, `secret_decrypted.txt` should match the original `secret.txt`.

## Security Considerations

While **Montgomery Chaos Lattices** is designed with strong cryptographic principles, consider the following to maintain security:

- **Montgomery Ladder Security**: The use of Montgomery ladders in lattice binding provides resistance against side-channel attacks by ensuring uniform execution paths. This technique is crucial for maintaining the confidentiality of the lattice structures.
  
- **Chaos-Based Randomness**: Chaotic sequences are employed to generate high-entropy pseudorandom numbers, enhancing the diffusion properties of the cipher. Ensure that the chaotic algorithms used are robust and free from predictable patterns.
  
- **Key Management**: Protect chaos keys (`chaos_key.pem`) securely. Compromise of the key can lead to decryption of sensitive data.
  
- **Randomness Source**: Ensure the underlying system's random number generator (used by `OsRng`) is secure and properly seeded to prevent predictability in key and sequence generation.
  
- **S-Box Integrity**: The bijective nature of the S-Box and its inverse must be maintained to ensure correct encryption and decryption. Any alteration can compromise the cipher's functionality.
  
- **Algorithm Review**: As a custom cipher, it hasn't undergone extensive peer review. Use it judiciously and consider professional audits for critical applications.
  
- **Updates**: Stay updated with the latest releases to benefit from security patches and improvements.

## Contributing

Contributions are welcome! Whether it's reporting bugs, suggesting features, or submitting pull requests, your input helps improve **Montgomery Chaos Lattices**.

## License

This project is licensed under the [MIT License](https://github.com/yourusername/montgomery-chaos-lattices/blob/main/LICENSE).

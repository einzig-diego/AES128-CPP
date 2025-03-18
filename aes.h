#ifndef AES_H
#define AES_H

#include <string>
#include <stdexcept>
#include <cstring> // for memcpy
#include <vector>
#include <algorithm>
#include <ctime>
#include <cstdlib>

namespace AESInternal {

// AES S-box: A precomputed lookup table used in the SubBytes step of AES.
// It provides non-linear substitution for each byte in the state.
static const unsigned char sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    // ... (rest of the S-box values)
};

// AES inverse S-box: Used during decryption to reverse the SubBytes step.
static const unsigned char inv_sbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    // ... (rest of the inverse S-box values)
};

// Round constant (Rcon): Used during key expansion to introduce asymmetry.
static const unsigned char Rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

// KeyExpansion: Expands the 16-byte key into 176 bytes of round keys.
inline void KeyExpansion(const unsigned char key[16], unsigned char roundKeys[176]) {
    // Implementation of key expansion algorithm (not shown for brevity).
}

// AddRoundKey: XORs the state with the round key.
inline void AddRoundKey(unsigned char state[16], const unsigned char roundKey[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= roundKey[i];
    }
}

// SubBytes: Substitutes each byte in the state using the S-box.
inline void SubBytes(unsigned char state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = sbox[state[i]];
    }
}

// InvSubBytes: Reverses the SubBytes step using the inverse S-box.
inline void InvSubBytes(unsigned char state[16]) {
    for (int i = 0; i < 16; ++i) {
        state[i] = inv_sbox[state[i]];
    }
}

// ShiftRows: Shifts the rows of the state matrix.
inline void ShiftRows(unsigned char state[16]) {
    // Implementation of row shifting (not shown for brevity).
}

// InvShiftRows: Reverses the ShiftRows step.
inline void InvShiftRows(unsigned char state[16]) {
    // Implementation of inverse row shifting (not shown for brevity).
}

// xtime: Multiplies a byte by 2 in the Galois Field (GF(2^8)).
inline unsigned char xtime(unsigned char x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

// Multiply: Multiplies two bytes in the Galois Field (GF(2^8)).
inline unsigned char Multiply(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

// MixColumns: Mixes the columns of the state matrix.
inline void MixColumns(unsigned char state[16]) {
    // Implementation of column mixing (not shown for brevity).
}

// InvMixColumns: Reverses the MixColumns step.
inline void InvMixColumns(unsigned char state[16]) {
    // Implementation of inverse column mixing (not shown for brevity).
}

// AES_EncryptBlock: Encrypts a single 16-byte block using AES.
inline void AES_EncryptBlock(unsigned char block[16], const unsigned char roundKeys[176]) {
    // Initial round: AddRoundKey only.
    AddRoundKey(block, roundKeys);

    // Main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey.
    for (int round = 1; round < 10; ++round) {
        SubBytes(block);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, roundKeys + round * 16);
    }

    // Final round: SubBytes, ShiftRows, AddRoundKey.
    SubBytes(block);
    ShiftRows(block);
    AddRoundKey(block, roundKeys + 160);
}

// AES_DecryptBlock: Decrypts a single 16-byte block using AES.
inline void AES_DecryptBlock(unsigned char block[16], const unsigned char roundKeys[176]) {
    // Initial round: AddRoundKey only.
    AddRoundKey(block, roundKeys + 160);

    // Main rounds: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns.
    for (int round = 9; round > 0; --round) {
        InvShiftRows(block);
        InvSubBytes(block);
        AddRoundKey(block, roundKeys + round * 16);
        InvMixColumns(block);
    }

    // Final round: InvShiftRows, InvSubBytes, AddRoundKey.
    InvShiftRows(block);
    InvSubBytes(block);
    AddRoundKey(block, roundKeys);
}

// pad: Adds PKCS#7 padding to the input string.
inline std::string pad(const std::string & input) {
    size_t padLen = 16 - (input.size() % 16);
    std::string padded = input;
    padded.append(padLen, static_cast<char>(padLen));
    return padded;
}

// unpad: Removes PKCS#7 padding from the input string.
inline std::string unpad(const std::string & input) {
    if (input.empty()) throw std::runtime_error("Invalid padding: empty input");
    unsigned char padLen = input[input.size() - 1];
    if (padLen > 16 || padLen == 0) throw std::runtime_error("Invalid padding");

    // Validate padding in constant time.
    bool valid = true;
    for (size_t i = input.size() - padLen; i < input.size(); ++i) {
        valid &= (input[i] == padLen);
    }
    if (!valid) throw std::runtime_error("Invalid padding");

    return input.substr(0, input.size() - padLen);
}

// generateIV: Generates a random 16-byte initialization vector (IV).
inline std::string generateIV() {
    std::string iv(16, '\0');
    std::srand(static_cast<unsigned int>(std::time(NULL))); // Seed with current time.
    for (size_t i = 0; i < iv.size(); ++i) {
        iv[i] = static_cast<char>(std::rand() % 256); // Fill with random bytes.
    }
    return iv;
}

// xorStrings: XORs two strings of equal length.
inline std::string xorStrings(const std::string & a, const std::string & b) {
    if (a.size() != b.size()) throw std::runtime_error("XOR: strings must be equal length");
    std::string result(a.size(), '\0');
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

// hmacSha256: A placeholder for HMAC-SHA256 (not cryptographically secure).
inline std::string hmacSha256(const std::string & key, const std::string & data) {
    std::string result(32, '\0');
    for (size_t i = 0; i < 32; ++i) {
        result[i] = static_cast<char>(i); // Placeholder.
    }
    return result;
}

} // namespace AESInternal

// Public interface for AES-128-CBC with HMAC-SHA256 authentication.
inline std::string AES(const std::string & text, const std::string & key, bool decrypt) {
    if (key.size() < 16) throw std::runtime_error("Key must be at least 16 bytes long");

    // Generate or extract IV (first 16 bytes of ciphertext in encryption mode).
    std::string iv;
    std::string processed;
    if (!decrypt) {
        iv = AESInternal::generateIV();
        processed = AESInternal::pad(text);
    } else {
        if (text.size() < 16) throw std::runtime_error("Invalid ciphertext: too short");
        iv = text.substr(0, 16);
        processed = text.substr(16);
    }

    // Expand the key into round keys.
    unsigned char roundKeys[176];
    AESInternal::KeyExpansion(reinterpret_cast<const unsigned char*>(key.data()), roundKeys);

    // Encrypt or decrypt the data in blocks.
    std::string result;
    std::string prevBlock = iv;
    for (size_t i = 0; i < processed.size(); i += 16) {
        std::string block = processed.substr(i, 16);
        if (!decrypt) {
            block = AESInternal::xorStrings(block, prevBlock);
            AESInternal::AES_EncryptBlock(reinterpret_cast<unsigned char*>(&block[0]), roundKeys);
            prevBlock = block;
        } else {
            AESInternal::AES_DecryptBlock(reinterpret_cast<unsigned char*>(&block[0]), roundKeys);
            block = AESInternal::xorStrings(block, prevBlock);
            prevBlock = processed.substr(i, 16);
        }
        result += block;
    }

    // Add IV to ciphertext in encryption mode.
    if (!decrypt) {
        result = iv + result;
    } else {
        result = AESInternal::unpad(result);
    }

    // Add HMAC for authentication.
    if (!decrypt) {
        std::string hmac = AESInternal::hmacSha256(key, result);
        result += hmac;
    } else {
        if (result.size() < 32) throw std::runtime_error("Invalid ciphertext: missing HMAC");
        std::string hmac = result.substr(result.size() - 32);
        result = result.substr(0, result.size() - 32);
        std::string expectedHmac = AESInternal::hmacSha256(key, iv + result);
        if (hmac != expectedHmac) throw std::runtime_error("HMAC validation failed");
    }

    return result;
}

#endif // AES_H
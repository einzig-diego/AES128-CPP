#ifndef AES_H
#define AES_H

#include <string>
#include <stdexcept>
#include <cstring> // for memcpy

// This header implements two overloads of AES() for encryption/decryption using AES-128 ECB mode.
// The implementation uses only <string>, <stdexcept> and <cstring> and is system independent.
// It assumes that the provided key is at least 16 characters long (only the first 16 bytes/chars are used).
// The text is padded with PKCS#7 on encryption and unpadded on decryption.
// The wchar_t version makes some assumptions (e.g. sizeof(wchar_t) divides 16) so use with care.

namespace AESInternal {

// AES S-box
static const unsigned char sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// AES inverse S-box
static const unsigned char inv_sbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

// Round constant (only first byte is used)
static const unsigned char Rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

// Expands a 16-byte key into 176 bytes (11 round keys of 16 bytes each).
inline void KeyExpansion(const unsigned char key[16], unsigned char roundKeys[176]) {
    std::memcpy(roundKeys, key, 16);
    int bytesGenerated = 16;
    int rconIteration = 1;
    unsigned char temp[4];

    while(bytesGenerated < 176) {
        for (int i = 0; i < 4; i++) {
            temp[i] = roundKeys[bytesGenerated - 4 + i];
        }
        if (bytesGenerated % 16 == 0) {
            // Rotate left
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // Substitute with S-box
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
            // XOR with round constant
            temp[0] ^= Rcon[rconIteration];
            ++rconIteration;
        }
        for (int i = 0; i < 4; i++) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            ++bytesGenerated;
        }
    }
}

inline void AddRoundKey(unsigned char state[16], const unsigned char roundKey[16]) {
    for (int i = 0; i < 16; i++)
        state[i] ^= roundKey[i];
}

inline void SubBytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
}

inline void InvSubBytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++)
        state[i] = inv_sbox[state[i]];
}

inline void ShiftRows(unsigned char state[16]) {
    unsigned char temp[16];
    // Row 0 (no shift)
    temp[0]  = state[0];
    temp[4]  = state[4];
    temp[8]  = state[8];
    temp[12] = state[12];
    // Row 1 (shift left by 1)
    temp[1]  = state[5];
    temp[5]  = state[9];
    temp[9]  = state[13];
    temp[13] = state[1];
    // Row 2 (shift left by 2)
    temp[2]  = state[10];
    temp[6]  = state[14];
    temp[10] = state[2];
    temp[14] = state[6];
    // Row 3 (shift left by 3)
    temp[3]  = state[15];
    temp[7]  = state[3];
    temp[11] = state[7];
    temp[15] = state[11];
    std::memcpy(state, temp, 16);
}

inline void InvShiftRows(unsigned char state[16]) {
    unsigned char temp[16];
    // Row 0 (no shift)
    temp[0]  = state[0];
    temp[4]  = state[4];
    temp[8]  = state[8];
    temp[12] = state[12];
    // Row 1 (shift right by 1)
    temp[1]  = state[13];
    temp[5]  = state[1];
    temp[9]  = state[5];
    temp[13] = state[9];
    // Row 2 (shift right by 2)
    temp[2]  = state[10];
    temp[6]  = state[14];
    temp[10] = state[2];
    temp[14] = state[6];
    // Row 3 (shift right by 3)
    temp[3]  = state[7];
    temp[7]  = state[11];
    temp[11] = state[15];
    temp[15] = state[3];
    std::memcpy(state, temp, 16);
}

// Helper: Multiply in GF(2^8)
inline unsigned char xtime(unsigned char x) {
    return (unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

inline unsigned char Multiply(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    while(b) {
        if(b & 1)
            result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

inline void MixColumns(unsigned char state[16]) {
    for (int i = 0; i < 4; i++) {
        int idx = i * 4;
        unsigned char a0 = state[idx];
        unsigned char a1 = state[idx + 1];
        unsigned char a2 = state[idx + 2];
        unsigned char a3 = state[idx + 3];
        state[idx]     = xtime(a0) ^ (a1 ^ xtime(a1)) ^ a2 ^ a3;
        state[idx + 1] = a0 ^ xtime(a1) ^ (a2 ^ xtime(a2)) ^ a3;
        state[idx + 2] = a0 ^ a1 ^ xtime(a2) ^ (a3 ^ xtime(a3));
        state[idx + 3] = (a0 ^ xtime(a0)) ^ a1 ^ a2 ^ xtime(a3);
    }
}

inline void InvMixColumns(unsigned char state[16]) {
    for (int i = 0; i < 4; i++) {
        int idx = i * 4;
        unsigned char a0 = state[idx];
        unsigned char a1 = state[idx + 1];
        unsigned char a2 = state[idx + 2];
        unsigned char a3 = state[idx + 3];
        state[idx]     = Multiply(a0, 0x0e) ^ Multiply(a1, 0x0b) ^ Multiply(a2, 0x0d) ^ Multiply(a3, 0x09);
        state[idx + 1] = Multiply(a0, 0x09) ^ Multiply(a1, 0x0e) ^ Multiply(a2, 0x0b) ^ Multiply(a3, 0x0d);
        state[idx + 2] = Multiply(a0, 0x0d) ^ Multiply(a1, 0x09) ^ Multiply(a2, 0x0e) ^ Multiply(a3, 0x0b);
        state[idx + 3] = Multiply(a0, 0x0b) ^ Multiply(a1, 0x0d) ^ Multiply(a2, 0x09) ^ Multiply(a3, 0x0e);
    }
}

inline void AES_EncryptBlock(unsigned char block[16], const unsigned char roundKeys[176]) {
    unsigned char state[16];
    std::memcpy(state, block, 16);
    AddRoundKey(state, roundKeys);
    for (int round = 1; round < 10; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 10 * 16);
    std::memcpy(block, state, 16);
}

inline void AES_DecryptBlock(unsigned char block[16], const unsigned char roundKeys[176]) {
    unsigned char state[16];
    std::memcpy(state, block, 16);
    AddRoundKey(state, roundKeys + 10 * 16);
    for (int round = 9; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);
    std::memcpy(block, state, 16);
}

// PKCS#7 padding for std::string (byte data)
inline std::string pad(const std::string & input) {
    std::string output = input;
    size_t padLen = 16 - (input.size() % 16);
    output.append(padLen, static_cast<char>(padLen));
    return output;
}

inline std::string unpad(const std::string & input) {
    if (input.empty()) return input;
    unsigned char padLen = input[input.size() - 1];
    if (padLen > 16)
        return input; // invalid padding, return as-is
    return input.substr(0, input.size() - padLen);
}

// PKCS#7 padding for std::wstring (treating each wchar_t as a unit)
// Note: This assumes that 16 is an exact multiple of sizeof(wchar_t).
inline std::wstring pad(const std::wstring & input) {
    std::wstring output = input;
    size_t padLen = 16 - ((input.size() * sizeof(wchar_t)) % 16 / sizeof(wchar_t));
    output.append(padLen, static_cast<wchar_t>(padLen));
    return output;
}

inline std::wstring unpad(const std::wstring & input) {
    if (input.empty()) return input;
    wchar_t padLen = input[input.size() - 1];
    if (padLen > 16)
        return input;
    return input.substr(0, input.size() - padLen);
}

} // namespace AESInternal

// Public interface for narrow strings.
inline std::string AES(const std::string & text, const std::string & key, bool decrypt) {
    if (key.size() < 16)
        throw std::runtime_error("Key must be at least 16 bytes long");
    unsigned char roundKeys[176];
    // Use only the first 16 bytes of the key.
    AESInternal::KeyExpansion(reinterpret_cast<const unsigned char*>(key.data()), roundKeys);

    std::string processed = text;
    if (!decrypt) {
        processed = AESInternal::pad(processed);
    } else {
        if (processed.size() % 16 != 0)
            throw std::runtime_error("Invalid ciphertext length");
    }
    for (size_t i = 0; i < processed.size(); i += 16) {
        unsigned char block[16];
        std::memcpy(block, processed.data() + i, 16);
        if (decrypt)
            AESInternal::AES_DecryptBlock(block, roundKeys);
        else
            AESInternal::AES_EncryptBlock(block, roundKeys);
        std::memcpy(&processed[i], block, 16);
    }
    if (decrypt)
        processed = AESInternal::unpad(processed);
    return processed;
}

// Public interface for wide strings.
inline std::wstring AES(const std::wstring & text, const std::wstring & key, bool decrypt) {
    if (key.size() < 16)
        throw std::runtime_error("Key must be at least 16 characters long");
    // For the wide string version we encrypt the underlying byte data.
    // This implementation assumes that sizeof(wchar_t) divides 16.
    if (16 % sizeof(wchar_t) != 0)
        throw std::runtime_error("Unsupported wchar_t size for AES");

    // Convert the first 16 wchar_t's of the key into 16 bytes.
    std::string keyBytes;
    keyBytes.resize(16);
    std::memcpy(&keyBytes[0], key.data(), 16);

    unsigned char roundKeys[176];
    AESInternal::KeyExpansion(reinterpret_cast<const unsigned char*>(keyBytes.data()), roundKeys);

    // Convert the wstring to a raw byte string.
    std::string raw;
    raw.resize(text.size() * sizeof(wchar_t));
    std::memcpy(&raw[0], text.data(), raw.size());

    if (!decrypt) {
        raw = AESInternal::pad(raw);
    } else {
        if (raw.size() % 16 != 0)
            throw std::runtime_error("Invalid ciphertext length");
    }
    for (size_t i = 0; i < raw.size(); i += 16) {
        unsigned char block[16];
        std::memcpy(block, raw.data() + i, 16);
        if (decrypt)
            AESInternal::AES_DecryptBlock(block, roundKeys);
        else
            AESInternal::AES_EncryptBlock(block, roundKeys);
        std::memcpy(&raw[i], block, 16);
    }
    if (decrypt)
        raw = AESInternal::unpad(raw);
    // Convert back to wstring.
    std::wstring result;
    result.resize(raw.size() / sizeof(wchar_t));
    std::memcpy(&result[0], raw.data(), raw.size());
    return result;
}

#endif // AES_H

#ifndef AES_H
#define AES_H

#include <algorithm>
#include <cstdlib>
#include <cstring> // for memcpy
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace AESInternal {

// AES S-box: A precomputed lookup table used in the SubBytes step of AES.
static const unsigned char sbox[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE,
  0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4,
  0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7,
  0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3,
  0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09,
  0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3,
  0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE,
  0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
  0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
  0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C,
  0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
  0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
  0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2,
  0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5,
  0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
  0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86,
  0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E,
  0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42,
  0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// AES inverse S-box: Used during decryption to reverse the SubBytes step.
static const unsigned char inv_sbox[256] = {
  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81,
  0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E,
  0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23,
  0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66,
  0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72,
  0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65,
  0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46,
  0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
  0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
  0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91,
  0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6,
  0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
  0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F,
  0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2,
  0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD, 0xA8,
  0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
  0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93,
  0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB,
  0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6,
  0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// Round constant (Rcon): Used during key expansion to introduce asymmetry.
static const unsigned char Rcon[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                        0x20, 0x40, 0x80, 0x1B, 0x36 };

// Helper to convert bytes to hex string for debugging
inline std::string
bytesToHex(const std::string& bytes)
{
  std::stringstream ss;
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    unsigned char c = static_cast<unsigned char>(bytes[i]);
    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
  }
  return ss.str();
}

// KeyExpansion: Expands the 16-byte key into 176 bytes of round keys.
inline void
KeyExpansion(const unsigned char key[16], unsigned char roundKeys[176])
{
  unsigned char temp[4];
  memcpy(roundKeys, key, 16);

  for (int i = 4; i < 44; ++i) {
    memcpy(temp, roundKeys + (i - 1) * 4, 4);
    if (i % 4 == 0) {
      // Rotate left
      unsigned char t = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = t;

      // SubBytes
      for (int j = 0; j < 4; ++j) {
        temp[j] = sbox[temp[j]];
      }

      // XOR with Rcon
      temp[0] ^= Rcon[i / 4];
    }
    for (int j = 0; j < 4; ++j) {
      roundKeys[i * 4 + j] = roundKeys[(i - 4) * 4 + j] ^ temp[j];
    }
  }
}

// AddRoundKey: XORs the state with the round key.
inline void
AddRoundKey(unsigned char state[16], const unsigned char roundKey[16])
{
  for (int i = 0; i < 16; ++i) {
    state[i] ^= roundKey[i];
  }
}

// SubBytes: Substitutes each byte in the state using the S-box.
inline void
SubBytes(unsigned char state[16])
{
  for (int i = 0; i < 16; ++i) {
    state[i] = sbox[state[i]];
  }
}

// InvSubBytes: Reverses the SubBytes step using the inverse S-box.
inline void
InvSubBytes(unsigned char state[16])
{
  for (int i = 0; i < 16; ++i) {
    state[i] = inv_sbox[state[i]];
  }
}

// ShiftRows: Shifts the rows of the state matrix.
inline void
ShiftRows(unsigned char state[16])
{
  unsigned char temp;

  // Row 1: No shift
  // Row 2: Shift left by 1
  temp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = temp;

  // Row 3: Shift left by 2
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  // Row 4: Shift left by 3
  temp = state[3];
  state[3] = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = temp;
}

// InvShiftRows: Reverses the ShiftRows step.
inline void
InvShiftRows(unsigned char state[16])
{
  unsigned char temp;

  // Row 1: No shift
  // Row 2: Shift right by 1
  temp = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = state[1];
  state[1] = temp;

  // Row 3: Shift right by 2
  temp = state[2];
  state[2] = state[10];
  state[10] = temp;
  temp = state[6];
  state[6] = state[14];
  state[14] = temp;

  // Row 4: Shift right by 3
  temp = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = temp;
}

// xtime: Multiplies a byte by 2 in the Galois Field (GF(2^8)).
inline unsigned char
xtime(unsigned char x)
{
  return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

// Multiply: Multiplies two bytes in the Galois Field (GF(2^8)).
inline unsigned char
Multiply(unsigned char a, unsigned char b)
{
  unsigned char result = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1)
      result ^= a;
    a = xtime(a);
    b >>= 1;
  }
  return result;
}

// MixColumns: Mixes the columns of the state matrix.
inline void
MixColumns(unsigned char state[16])
{
  for (int i = 0; i < 16; i += 4) {
    unsigned char s0 = state[i], s1 = state[i + 1], s2 = state[i + 2],
                  s3 = state[i + 3];
    state[i] = Multiply(s0, 2) ^ Multiply(s1, 3) ^ s2 ^ s3;
    state[i + 1] = s0 ^ Multiply(s1, 2) ^ Multiply(s2, 3) ^ s3;
    state[i + 2] = s0 ^ s1 ^ Multiply(s2, 2) ^ Multiply(s3, 3);
    state[i + 3] = Multiply(s0, 3) ^ s1 ^ s2 ^ Multiply(s3, 2);
  }
}

// InvMixColumns: Reverses the MixColumns step.
inline void
InvMixColumns(unsigned char state[16])
{
  for (int i = 0; i < 16; i += 4) {
    unsigned char s0 = state[i], s1 = state[i + 1], s2 = state[i + 2],
                  s3 = state[i + 3];
    state[i] = Multiply(s0, 0x0E) ^ Multiply(s1, 0x0B) ^ Multiply(s2, 0x0D) ^
               Multiply(s3, 0x09);
    state[i + 1] = Multiply(s0, 0x09) ^ Multiply(s1, 0x0E) ^
                   Multiply(s2, 0x0B) ^ Multiply(s3, 0x0D);
    state[i + 2] = Multiply(s0, 0x0D) ^ Multiply(s1, 0x09) ^
                   Multiply(s2, 0x0E) ^ Multiply(s3, 0x0B);
    state[i + 3] = Multiply(s0, 0x0B) ^ Multiply(s1, 0x0D) ^
                   Multiply(s2, 0x09) ^ Multiply(s3, 0x0E);
  }
}

// AES_EncryptBlock: Encrypts a single 16-byte block using AES.
inline void
AES_EncryptBlock(unsigned char block[16], const unsigned char roundKeys[176])
{
  AddRoundKey(block, roundKeys);

  for (int round = 1; round < 10; ++round) {
    SubBytes(block);
    ShiftRows(block);
    MixColumns(block);
    AddRoundKey(block, roundKeys + round * 16);
  }

  SubBytes(block);
  ShiftRows(block);
  AddRoundKey(block, roundKeys + 160);
}

// AES_DecryptBlock: Decrypts a single 16-byte block using AES.
inline void
AES_DecryptBlock(unsigned char block[16], const unsigned char roundKeys[176])
{
  AddRoundKey(block, roundKeys + 160);

  for (int round = 9; round > 0; --round) {
    InvShiftRows(block);
    InvSubBytes(block);
    AddRoundKey(block, roundKeys + round * 16);
    InvMixColumns(block);
  }

  InvShiftRows(block);
  InvSubBytes(block);
  AddRoundKey(block, roundKeys);
}

// pad: Adds PKCS#7 padding to the input string.
inline std::string
pad(const std::string& input)
{
  size_t padLen = 16 - (input.size() % 16);
  std::string padded = input;
  padded.append(padLen, static_cast<char>(padLen));
  return padded;
}

// unpad: Removes PKCS#7 padding from the input string.
inline std::string
unpad(const std::string& input)
{
  if (input.empty())
    throw std::runtime_error("Invalid padding: empty input");
  unsigned char padLen = input[input.size() - 1];
  if (padLen > 16 || padLen == 0)
    throw std::runtime_error("Invalid padding");

  bool valid = true;
  for (size_t i = input.size() - padLen; i < input.size(); ++i) {
    valid &= (input[i] == padLen);
  }
  if (!valid)
    throw std::runtime_error("Invalid padding");

  return input.substr(0, input.size() - padLen);
}

// generateIV: Generates a random 16-byte initialization vector (IV).
inline std::string
generateIV()
{
  std::string iv(16, '\0');
  std::srand(static_cast<unsigned int>(std::time(NULL)));
  for (size_t i = 0; i < iv.size(); ++i) {
    iv[i] = static_cast<char>(std::rand() % 256);
  }
  return iv;
}

// xorStrings: XORs two strings of equal length.
inline std::string
xorStrings(const std::string& a, const std::string& b)
{
  if (a.size() != b.size())
    throw std::runtime_error("XOR: strings must be equal length");
  std::string result(a.size(), '\0');
  for (size_t i = 0; i < a.size(); ++i) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

// SHA-256 constants
static const unsigned int k[64] = {
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
  0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
  0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
  0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
  0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
  0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
  0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
  0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
  0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
  0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
  0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

// SHA-256 functions
inline unsigned int
rotr(unsigned int x, unsigned int n)
{
  return (x >> n) | (x << (32 - n));
}

inline unsigned int
ch(unsigned int x, unsigned int y, unsigned int z)
{
  return (x & y) ^ (~x & z);
}

inline unsigned int
maj(unsigned int x, unsigned int y, unsigned int z)
{
  return (x & y) ^ (x & z) ^ (y & z);
}

inline unsigned int
sigma0(unsigned int x)
{
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline unsigned int
sigma1(unsigned int x)
{
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline unsigned int
gamma0(unsigned int x)
{
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline unsigned int
gamma1(unsigned int x)
{
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA-256 hash function
// Modified SHA-256 to return raw bytes
inline std::string
sha256(const std::string& input)
{
  unsigned int h[8] = { 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
                        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

  std::string data = input;
  data.push_back(0x80);

  while ((data.size() + 8) % 64 != 0) {
    data.push_back(0x00);
  }

  unsigned long long bitLength = input.size() * 8;
  for (int i = 7; i >= 0; --i) {
    data.push_back((bitLength >> (i * 8)) & 0xFF);
  }

  for (size_t i = 0; i < data.size(); i += 64) {
    unsigned int w[64];
    for (int t = 0; t < 16; ++t) {
      w[t] = (static_cast<unsigned char>(data[i + t * 4]) << 24) |
             (static_cast<unsigned char>(data[i + t * 4 + 1]) << 16) |
             (static_cast<unsigned char>(data[i + t * 4 + 2]) << 8) |
             static_cast<unsigned char>(data[i + t * 4 + 3]);
    }
    for (int t = 16; t < 64; ++t) {
      w[t] = gamma1(w[t - 2]) + w[t - 7] + gamma0(w[t - 15]) + w[t - 16];
    }

    unsigned int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5],
                 g = h[6], hh = h[7];

    for (int t = 0; t < 64; ++t) {
      unsigned int t1 = hh + sigma1(e) + ch(e, f, g) + k[t] + w[t];
      unsigned int t2 = sigma0(a) + maj(a, b, c);
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }

  // Convert hash to raw bytes
  std::string result;
  for (int i = 0; i < 8; ++i) {
    result.push_back(static_cast<char>((h[i] >> 24) & 0xFF));
    result.push_back(static_cast<char>((h[i] >> 16) & 0xFF));
    result.push_back(static_cast<char>((h[i] >> 8) & 0xFF));
    result.push_back(static_cast<char>(h[i] & 0xFF));
  }
  return result;
}

// HMAC-SHA256: Computes the HMAC using SHA-256.
inline std::string
hmacSha256(const std::string& key, const std::string& data)
{
  const unsigned int blockSize = 64;
  std::string keyCopy = key;

  if (keyCopy.size() > blockSize) {
    keyCopy = sha256(keyCopy);
  }

  keyCopy.resize(blockSize, 0x00);

  std::string innerKey = keyCopy;
  std::string outerKey = keyCopy;
  for (size_t i = 0; i < blockSize; ++i) {
    innerKey[i] ^= 0x36;
    outerKey[i] ^= 0x5C;
  }

  std::string innerHash = sha256(innerKey + data);
  return sha256(outerKey + innerHash);
}
} // namespace AESInternal

// Public interface for AES-128-CBC with HMAC-SHA256 authentication.
inline std::string
AES(const std::string& text, const std::string& key, bool decrypt)
{
  if (key.size() < 16)
    throw std::runtime_error("Key must be at least 16 bytes long");

  std::string iv;
  std::string processed;
  if (!decrypt) {
    iv = AESInternal::generateIV();
    processed = AESInternal::pad(text);
  } else {
    if (text.size() < 16 + 32)
      throw std::runtime_error("Invalid ciphertext: too short");
    iv = text.substr(0, 16);
    std::string ciphertextWithHMAC = text.substr(16);
    std::string hmac =
      ciphertextWithHMAC.substr(ciphertextWithHMAC.size() - 32);
    processed = ciphertextWithHMAC.substr(0, ciphertextWithHMAC.size() - 32);

    std::string hmacInput = iv + processed;
    std::string expectedHmac = AESInternal::hmacSha256(key, hmacInput);

    if (hmac != expectedHmac)
      throw std::runtime_error("HMAC validation failed");
  }

  unsigned char roundKeys[176];
  AESInternal::KeyExpansion(reinterpret_cast<const unsigned char*>(key.data()),
                            roundKeys);

  std::string result;
  std::string prevBlock = iv;
  for (size_t i = 0; i < processed.size(); i += 16) {
    std::string block = processed.substr(i, 16);
    if (block.size() < 16)
      block.append(16 - block.size(), '\0');

    if (!decrypt) {
      block = AESInternal::xorStrings(block, prevBlock);
      AESInternal::AES_EncryptBlock(reinterpret_cast<unsigned char*>(&block[0]),
                                    roundKeys);
      prevBlock = block;
    } else {
      AESInternal::AES_DecryptBlock(reinterpret_cast<unsigned char*>(&block[0]),
                                    roundKeys);
      block = AESInternal::xorStrings(block, prevBlock);
      prevBlock = processed.substr(i, 16);
    }
    result += block;
  }

  if (!decrypt) {
    std::string hmacInput = iv + result;
    std::string hmac = AESInternal::hmacSha256(key, hmacInput);
    result = iv + result + hmac;
  } else {
    result = AESInternal::unpad(result);
  }

  return result;
}
#endif // AES_H

// Copyright © 2026 Racpast. All Rights Reserved.
//
// This file is part of SNIBypassGUI, a proprietary software project.
//
// NOTICE: All information contained herein is, and remains the property of
// Racpast. The intellectual and technical concepts contained herein are
// proprietary to Racpast and are protected by copyright law and international
// treaties. Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained from Racpast.
//
// Unauthorized copying, modification, distribution, or use of this file,
// via any medium, is strictly prohibited.
//
// For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com
//
// See the LICENSE file in the project root for full terms and conditions.

#include "update/crypto.h"

#include <windows.h>

#include <bcrypt.h>

#include <cstring>

#include "app/logging.h"
#include "update/public_key.h"

namespace Crypto {
namespace {

std::wstring ToHex(const uint8_t* d, size_t n) {
    static const wchar_t kDigits[] = L"0123456789abcdef";
    std::wstring s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(kDigits[d[i] >> 4]);
        s.push_back(kDigits[d[i] & 0xF]);
    }
    return s;
}

}  // namespace

Sha256::Sha256() {
    auto* alg = reinterpret_cast<BCRYPT_ALG_HANDLE*>(&alg_);
    if (BCryptOpenAlgorithmProvider(alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return;
    DWORD objectLength = 0;
    DWORD written = 0;
    BCryptGetProperty(*alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength),
                      sizeof(objectLength), &written, 0);
    BCryptGetProperty(*alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&length_),
                      sizeof(length_), &written, 0);
    object_.resize(objectLength);
    auto* hash = reinterpret_cast<BCRYPT_HASH_HANDLE*>(&hash_);
    if (BCryptCreateHash(*alg, hash, object_.data(), objectLength, nullptr, 0, 0) != 0)
        hash_ = nullptr;
}

Sha256::~Sha256() {
    if (hash_) BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(hash_));
    if (alg_) BCryptCloseAlgorithmProvider(static_cast<BCRYPT_ALG_HANDLE>(alg_), 0);
}

void Sha256::Add(const void* data, size_t n) {
    if (!hash_ || n == 0) return;
    BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(hash_),
                   static_cast<PUCHAR>(const_cast<void*>(data)), static_cast<ULONG>(n), 0);
}

bool Sha256::Digest(std::vector<uint8_t>& out) {
    if (!hash_) return false;
    out.assign(length_, 0);
    return BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(hash_), out.data(), length_, 0) ==
           0;
}

std::wstring Sha256::Hex() {
    std::vector<uint8_t> digest;
    if (!Digest(digest)) return L"";
    return ToHex(digest.data(), digest.size());
}

std::wstring Sha256Hex(const void* data, size_t n) {
    Sha256 h;
    if (!h.valid()) return L"";
    h.Add(data, n);
    return h.Hex();
}

bool Base64Decode(const std::string& in, std::vector<uint8_t>& out) {
    const auto sextet = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    out.clear();
    int accumulator = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        const int v = sextet(c);
        if (v < 0) return false;
        accumulator = (accumulator << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((accumulator >> bits) & 0xFF));
        }
    }
    return true;
}

// The signature is raw r||s (64 bytes), exactly what CNG expects. The public key is
// the uncompressed point X||Y (64 bytes), wrapped in a BCRYPT_ECCKEY_BLOB for import.
bool VerifySignature(const std::string& message, const std::vector<uint8_t>& signature) {
    if (signature.size() != 64) {
        LOGE(L"Update: signature is " + std::to_wstring(signature.size()) +
             L" bytes, expected 64.");
        return false;
    }

    Sha256 hash;
    if (!hash.valid()) return false;
    hash.Add(message.data(), message.size());
    std::vector<uint8_t> digest;
    if (!hash.Digest(digest)) return false;

    std::vector<uint8_t> blob(sizeof(BCRYPT_ECCKEY_BLOB) + sizeof(kUpdatePublicKey));
    auto* header = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    header->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    header->cbKey = 32;  // per-coordinate size
    std::memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), kUpdatePublicKey,
                sizeof(kUpdatePublicKey));

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0) {
        LOGE(L"Update: cannot open the ECDSA P-256 provider.");
        return false;
    }

    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS status = BCryptImportKeyPair(alg, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key,
                                          blob.data(), static_cast<ULONG>(blob.size()), 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        LOGE(L"Update: cannot import the update public key.");
        return false;
    }

    status = BCryptVerifySignature(
        key, nullptr, digest.data(), static_cast<ULONG>(digest.size()),
        const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()), 0);
    BCryptDestroyKey(key);
    BCryptCloseAlgorithmProvider(alg, 0);
    return status == 0;
}

}  // namespace Crypto

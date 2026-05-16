/*
 *  hkdf.h
 *
 *  Copyright (C) 2024, 2026
 *  Terrapane Corporation
 *  All Rights Reserved
 *
 *  Author:
 *      Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This file defines an object called HKDF that performs the
 *      Hash-based Message Authentication Code (HMAC) Key Derivation Function
 *      (KDF) procedures defined in RFC 5869.
 *
 *      There are two forms of the constructor.  The first takes only a
 *      hash algorithm, while the second accepts an optional salt value,
 *      "Input Keying Material" (IKM), and hash algorithm.
 *
 *      With the first form, the user must call the Extract() function later
 *      with (optional) salt value and "Input Keying Material" (IKM).  Then,
 *      the user may call Expand() to get additional derived data.
 *
 *      In the second form, the constructor will invoke the Extract() function
 *      upon construction.  As such, the user may immediately call Expand().
 *
 *      At any time, the object may be reinitialized with a new salt and
 *      IKM by calling Extract().
 *
 *  Portability Issues:
 *      None.
 */

#pragma once

#include <vector>
#include <span>
#include <cstdint>
#include <cstddef>
#include <terra/crypto/hash/hmac.h>
#include <terra/crypto/kdf/kdf_exception.h>

namespace Terra::Crypto::KDF
{

class HKDF
{
    public:
        explicit HKDF(Hash::HashAlgorithm algorithm);
        HKDF(const HKDF &other) = default;
        HKDF(HKDF &&other) = default;
        HKDF(Hash::HashAlgorithm algorithm,
             std::span<const std::uint8_t> ikm,
             std::span<const std::uint8_t> salt = {});
        ~HKDF();

        HKDF &operator=(const HKDF &other) = default;
        HKDF &operator=(HKDF &&other) = default;

        void Extract(std::span<const std::uint8_t> ikm,
                     std::span<const std::uint8_t> salt = {});
        std::span<std::uint8_t> Expand(std::span<const std::uint8_t> info,
                                       std::span<std::uint8_t> key);
        std::span<std::uint8_t> Expand(std::span<const char> info,
                                       std::span<std::uint8_t> key);

        std::size_t GetHMACLength() const noexcept
        {
            return hmac.GetHMACLength();
        }

    protected:
        Hash::HMAC hmac;
        std::size_t hash_length;
        bool keyed;
};

} // namespace Terra::Crypto::KDF

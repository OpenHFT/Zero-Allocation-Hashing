/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 *
 * From the repository root:
 * git clone https://github.com/aappleby/smhasher.git /tmp/smhasher-seeds
 * git -C /tmp/smhasher-seeds checkout 07bb4de10a63e8cc2e1724865454eba635742383
 * c++ -std=c++11 -I/tmp/smhasher-seeds/src /tmp/smhasher-seeds/src/MurmurHash3.cpp \
 *     src/test/resources/murmur3-seed-vectors.cpp -o /tmp/murmur3-seed-vectors
 * /tmp/murmur3-seed-vectors
 */
#include "MurmurHash3.h"
#include <cinttypes>
#include <cstdio>
#include <cstring>

int main() {
    const char* data = "The quick brown fox jumps over the lazy dog";
    const uint32_t seeds[] = {0x80000000u, 0xffffffffu};
    for (uint32_t seed : seeds) {
        uint64_t hash[2];
        MurmurHash3_x64_128(data, std::strlen(data), seed, hash);
        std::printf("%08" PRIx32 ": %016" PRIx64 " %016" PRIx64 "\n", seed, hash[0], hash[1]);
    }
}

/*
 * Copyright 2015 Higher Frequency Trading http://www.higherfrequencytrading.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openhft.hashing;

import java.nio.ByteBuffer;

import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static net.openhft.hashing.Maths.unsignedLongMulXorFold;
import static net.openhft.hashing.UnsafeAccess.*;
import static net.openhft.hashing.Util.NATIVE_LITTLE_ENDIAN;

/**
 * Adapted version of XXH3 implementation from https://github.com/Cyan4973/xxHash.
 * This implementation provides endian-independant hash values, but it's slower on big-endian platforms.
 */
class XXH3 {
    private static final Access<Object> unsafeLE = UnsafeAccess.INSTANCE.byteOrder(null, LITTLE_ENDIAN);

    /*! Pseudorandom secret taken directly from FARSH. */
    private static final byte[] XXH3_kSecret = {
        (byte)0xb8, (byte)0xfe, (byte)0x6c, (byte)0x39, (byte)0x23, (byte)0xa4, (byte)0x4b, (byte)0xbe, (byte)0x7c, (byte)0x01, (byte)0x81, (byte)0x2c, (byte)0xf7, (byte)0x21, (byte)0xad, (byte)0x1c,
        (byte)0xde, (byte)0xd4, (byte)0x6d, (byte)0xe9, (byte)0x83, (byte)0x90, (byte)0x97, (byte)0xdb, (byte)0x72, (byte)0x40, (byte)0xa4, (byte)0xa4, (byte)0xb7, (byte)0xb3, (byte)0x67, (byte)0x1f,
        (byte)0xcb, (byte)0x79, (byte)0xe6, (byte)0x4e, (byte)0xcc, (byte)0xc0, (byte)0xe5, (byte)0x78, (byte)0x82, (byte)0x5a, (byte)0xd0, (byte)0x7d, (byte)0xcc, (byte)0xff, (byte)0x72, (byte)0x21,
        (byte)0xb8, (byte)0x08, (byte)0x46, (byte)0x74, (byte)0xf7, (byte)0x43, (byte)0x24, (byte)0x8e, (byte)0xe0, (byte)0x35, (byte)0x90, (byte)0xe6, (byte)0x81, (byte)0x3a, (byte)0x26, (byte)0x4c,
        (byte)0x3c, (byte)0x28, (byte)0x52, (byte)0xbb, (byte)0x91, (byte)0xc3, (byte)0x00, (byte)0xcb, (byte)0x88, (byte)0xd0, (byte)0x65, (byte)0x8b, (byte)0x1b, (byte)0x53, (byte)0x2e, (byte)0xa3,
        (byte)0x71, (byte)0x64, (byte)0x48, (byte)0x97, (byte)0xa2, (byte)0x0d, (byte)0xf9, (byte)0x4e, (byte)0x38, (byte)0x19, (byte)0xef, (byte)0x46, (byte)0xa9, (byte)0xde, (byte)0xac, (byte)0xd8,
        (byte)0xa8, (byte)0xfa, (byte)0x76, (byte)0x3f, (byte)0xe3, (byte)0x9c, (byte)0x34, (byte)0x3f, (byte)0xf9, (byte)0xdc, (byte)0xbb, (byte)0xc7, (byte)0xc7, (byte)0x0b, (byte)0x4f, (byte)0x1d,
        (byte)0x8a, (byte)0x51, (byte)0xe0, (byte)0x4b, (byte)0xcd, (byte)0xb4, (byte)0x59, (byte)0x31, (byte)0xc8, (byte)0x9f, (byte)0x7e, (byte)0xc9, (byte)0xd9, (byte)0x78, (byte)0x73, (byte)0x64,
        (byte)0xea, (byte)0xc5, (byte)0xac, (byte)0x83, (byte)0x34, (byte)0xd3, (byte)0xeb, (byte)0xc3, (byte)0xc5, (byte)0x81, (byte)0xa0, (byte)0xff, (byte)0xfa, (byte)0x13, (byte)0x63, (byte)0xeb,
        (byte)0x17, (byte)0x0d, (byte)0xdd, (byte)0x51, (byte)0xb7, (byte)0xf0, (byte)0xda, (byte)0x49, (byte)0xd3, (byte)0x16, (byte)0x55, (byte)0x26, (byte)0x29, (byte)0xd4, (byte)0x68, (byte)0x9e,
        (byte)0x2b, (byte)0x16, (byte)0xbe, (byte)0x58, (byte)0x7d, (byte)0x47, (byte)0xa1, (byte)0xfc, (byte)0x8f, (byte)0xf8, (byte)0xb8, (byte)0xd1, (byte)0x7a, (byte)0xd0, (byte)0x31, (byte)0xce,
        (byte)0x45, (byte)0xcb, (byte)0x3a, (byte)0x8f, (byte)0x95, (byte)0x16, (byte)0x04, (byte)0x28, (byte)0xaf, (byte)0xd7, (byte)0xfb, (byte)0xca, (byte)0xbb, (byte)0x4b, (byte)0x40, (byte)0x7e,
    };

    // Primes
    private static final long XXH_PRIME32_1 = 0x9E3779B1L;   /*!< 0b10011110001101110111100110110001 */
    private static final long XXH_PRIME32_2 = 0x85EBCA77L;   /*!< 0b10000101111010111100101001110111 */
    private static final long XXH_PRIME32_3 = 0xC2B2AE3DL;   /*!< 0b11000010101100101010111000111101 */

    private static final long XXH_PRIME64_1 = 0x9E3779B185EBCA87L;   /*!< 0b1001111000110111011110011011000110000101111010111100101010000111 */
    private static final long XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4FL;   /*!< 0b1100001010110010101011100011110100100111110101001110101101001111 */
    private static final long XXH_PRIME64_3 = 0x165667B19E3779F9L;   /*!< 0b0001011001010110011001111011000110011110001101110111100111111001 */
    private static final long XXH_PRIME64_4 = 0x85EBCA77C2B2AE63L;   /*!< 0b1000010111101011110010100111011111000010101100101010111001100011 */
    private static final long XXH_PRIME64_5 = 0x27D4EB2F165667C5L;   /*!< 0b0010011111010100111010110010111100010110010101100110011111000101 */

    // only support fixed size secret
    private static final long nbStripesPerBlock = (192 - 64) / 8;
    private static final long block_len = 64 * nbStripesPerBlock;

    private static long XXH64_avalanche(long h64) {
        h64 ^= h64 >>> 33;
        h64 *= XXH_PRIME64_2;
        h64 ^= h64 >>> 29;
        h64 *= XXH_PRIME64_3;
        return h64 ^ (h64 >>> 32);
    }
    private static long XXH3_avalanche(long h64) {
        h64 ^= h64 >>> 37;
        h64 *= 0x165667919E3779F9L;
        return h64 ^ (h64 >>> 32);
    }
    private static long XXH3_rrmxmx(long h64, final long length) {
        h64 ^= Long.rotateLeft(h64, 49) ^ Long.rotateLeft(h64, 24);
        h64 *= 0x9FB21C651E98DF25L;
        h64 ^= (h64 >>> 35) + length;
        h64 *= 0x9FB21C651E98DF25L;
        return h64 ^ (h64 >>> 28);
    }

    private static <T> long XXH3_mix16B(final long seed, final T input, final Access<T> access, final long offIn, final long offSec) {
        final long input_lo = access.i64(input, offIn);
        final long input_hi = access.i64(input, offIn + 8);
        return unsignedLongMulXorFold(
            input_lo ^ (unsafeLE.i64(XXH3_kSecret, offSec)   + seed),
            input_hi ^ (unsafeLE.i64(XXH3_kSecret, offSec+8) - seed)
        );
    }

    /*
     * A bit slower than XXH3_mix16B, but handles multiply by zero better.
     */
    private static <T> void XXH128_mix32B(final long seed, final T input, final Access<T> access, final long offIn1, final long offIn2, final long offSec, final long acc[]) {
        acc[0] += XXH3_mix16B(seed, input, access, offIn1, offSec);
        acc[0] ^= access.i64(input, offIn2) + access.i64(input, offIn2 + 8);
        acc[1] += XXH3_mix16B (seed, input, access, offIn2, offSec + 16);
        acc[1] ^= access.i64(input, offIn1) + access.i64(input, offIn1 + 8);
    }

    private static long XXH3_mix2Accs(final long acc_lh, final long acc_rh, final byte[] secret, final long offSec) {
        return unsignedLongMulXorFold(
            acc_lh ^ unsafeLE.i64(secret, offSec),
            acc_rh ^ unsafeLE.i64(secret, offSec+8) );
    }

    private static <T> long XXH3_64bits_internal(final long seed, final byte[] secret, final T input, final Access<T> access, final long off, final long length) {
        if (length <= 16) {
            // XXH3_len_0to16_64b
            if (length > 8) {
                // XXH3_len_9to16_64b
                final long bitflip1 = (unsafeLE.i64(XXH3_kSecret, 24+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 32+BYTE_BASE)) + seed;
                final long bitflip2 = (unsafeLE.i64(XXH3_kSecret, 40+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 48+BYTE_BASE)) - seed;
                final long input_lo = access.i64(input, off) ^ bitflip1;
                final long input_hi = access.i64(input, off + length - 8) ^ bitflip2;
                final long acc = length + Long.reverseBytes(input_lo) + input_hi + unsignedLongMulXorFold(input_lo, input_hi);
                return XXH3_avalanche(acc);
            }
            if (length >= 4) {
                // XXH3_len_4to8_64b
                long s = seed ^ Long.reverseBytes(seed & 0xFFFFFFFFL);
                final long input1 = (long)access.i32(input, off); // high int will be shifted
                final long input2 = access.u32(input, off + length - 4);
                final long bitflip = (unsafeLE.i64(XXH3_kSecret, 8+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 16+BYTE_BASE)) - s;
                final long keyed = (input2 + (input1 << 32)) ^ bitflip;
                return XXH3_rrmxmx(keyed, length);
            }
            if (length != 0) {
                // XXH3_len_1to3_64b
                final int c1 = access.u8(input, off + 0);
                final int c2 = access.i8(input, off + (length >> 1)); // high 3 bytes will be shifted
                final int c3 = access.u8(input, off + length - 1);
                final long combined = Primitives.unsignedInt((c1 << 16) | (c2  << 24) | c3 | ((int)length << 8));
                final long bitflip = Primitives.unsignedInt(unsafeLE.i32(XXH3_kSecret, BYTE_BASE) ^ unsafeLE.i32(XXH3_kSecret, 4+BYTE_BASE)) + seed;
                return XXH64_avalanche(combined ^ bitflip);
            }
            return XXH64_avalanche(seed ^ unsafeLE.i64(XXH3_kSecret, 56+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 64+BYTE_BASE));
        }
        if (length <= 128) {
            // XXH3_len_17to128_64b
            long acc = length * XXH_PRIME64_1;

            if (length > 32) {
                if (length > 64) {
                    if (length > 96) {
                        acc += XXH3_mix16B(seed, input, access, off + 48, BYTE_BASE + 96);
                        acc += XXH3_mix16B(seed, input, access, off + length - 64, BYTE_BASE + 112);
                    }
                    acc += XXH3_mix16B(seed, input, access, off + 32, BYTE_BASE + 64);
                    acc += XXH3_mix16B(seed, input, access, off + length - 48, BYTE_BASE + 80);
                }
                acc += XXH3_mix16B(seed, input, access, off + 16, BYTE_BASE + 32);
                acc += XXH3_mix16B(seed, input, access, off + length - 32, BYTE_BASE + 48);
            }
            acc += XXH3_mix16B(seed, input, access, off, BYTE_BASE);
            acc += XXH3_mix16B(seed, input, access, off + length - 16, BYTE_BASE + 16);

            return XXH3_avalanche(acc);
        }
        if (length <= 240) {
            // XXH3_len_129to240_64b
            long acc = length * XXH_PRIME64_1;
            final int nbRounds = (int)length / 16;
            int i = 0;
            for (; i < 8; ++i) {
                acc += XXH3_mix16B(seed, input, access, off + 16*i, BYTE_BASE + 16*i);
            }
            acc = XXH3_avalanche(acc);

            for (; i < nbRounds; ++i) {
                acc += XXH3_mix16B(seed, input, access, off + 16*i, BYTE_BASE + 16*(i-8) + 3);
            }

            /* last bytes */
            acc += XXH3_mix16B(seed, input, access, off + length - 16, BYTE_BASE + 136 - 17);
            return XXH3_avalanche(acc);
        }

        // XXH3_hashLong_64b_internal
        long acc_0 = XXH_PRIME32_3;
        long acc_1 = XXH_PRIME64_1;
        long acc_2 = XXH_PRIME64_2;
        long acc_3 = XXH_PRIME64_3;
        long acc_4 = XXH_PRIME64_4;
        long acc_5 = XXH_PRIME32_2;
        long acc_6 = XXH_PRIME64_5;
        long acc_7 = XXH_PRIME32_1;

        // XXH3_hashLong_internal_loop
        final long nb_blocks = (length - 1) / block_len;
        for (long n = 0; n < nb_blocks; n++) {
            // XXH3_accumulate
            final long offBlock = off + n * block_len;
            for (long s = 0; s < nbStripesPerBlock; s++ ) {
                // XXH3_accumulate_512
                final long offStripe = offBlock + s * 64;
                final long offSec = s * 8;
                {
                    final long data_val_0 = access.i64(input, offStripe + 8*0);
                    final long data_val_1 = access.i64(input, offStripe + 8*1);
                    final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*0);
                    final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*1);
                    /* swap adjacent lanes */
                    acc_0 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                    acc_1 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
                }
                {
                    final long data_val_0 = access.i64(input, offStripe + 8*2);
                    final long data_val_1 = access.i64(input, offStripe + 8*3);
                    final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*2);
                    final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*3);
                    /* swap adjacent lanes */
                    acc_2 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                    acc_3 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
                }
                {
                    final long data_val_0 = access.i64(input, offStripe + 8*4);
                    final long data_val_1 = access.i64(input, offStripe + 8*5);
                    final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*4);
                    final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*5);
                    /* swap adjacent lanes */
                    acc_4 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                    acc_5 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
                }
                {
                    final long data_val_0 = access.i64(input, offStripe + 8*6);
                    final long data_val_1 = access.i64(input, offStripe + 8*7);
                    final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*6);
                    final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*7);
                    /* swap adjacent lanes */
                    acc_6 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                    acc_7 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
                }
            }

            // XXH3_scrambleAcc_scalar
            final long offSec = BYTE_BASE + 192 - 64;
            acc_0 = (acc_0 ^ (acc_0 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*0)) * XXH_PRIME32_1;
            acc_1 = (acc_1 ^ (acc_1 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*1)) * XXH_PRIME32_1;
            acc_2 = (acc_2 ^ (acc_2 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*2)) * XXH_PRIME32_1;
            acc_3 = (acc_3 ^ (acc_3 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*3)) * XXH_PRIME32_1;
            acc_4 = (acc_4 ^ (acc_4 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*4)) * XXH_PRIME32_1;
            acc_5 = (acc_5 ^ (acc_5 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*5)) * XXH_PRIME32_1;
            acc_6 = (acc_6 ^ (acc_6 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*6)) * XXH_PRIME32_1;
            acc_7 = (acc_7 ^ (acc_7 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*7)) * XXH_PRIME32_1;
        }

        /* last partial block */
        final long nbStripes = ((length - 1) - (block_len * nb_blocks)) / 64;
        final long offBlock = off + block_len * nb_blocks;
        for (long s = 0; s < nbStripes; s++) {
            // XXH3_accumulate_512
            final long offStripe = offBlock + s * 64;
            final long offSec = s * 8;
            {
                final long data_val_0 = access.i64(input, offStripe + 8*0);
                final long data_val_1 = access.i64(input, offStripe + 8*1);
                final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*0);
                final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*1);
                /* swap adjacent lanes */
                acc_0 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                acc_1 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
            }
            {
                final long data_val_0 = access.i64(input, offStripe + 8*2);
                final long data_val_1 = access.i64(input, offStripe + 8*3);
                final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*2);
                final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*3);
                /* swap adjacent lanes */
                acc_2 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                acc_3 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
            }
            {
                final long data_val_0 = access.i64(input, offStripe + 8*4);
                final long data_val_1 = access.i64(input, offStripe + 8*5);
                final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*4);
                final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*5);
                /* swap adjacent lanes */
                acc_4 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                acc_5 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
            }
            {
                final long data_val_0 = access.i64(input, offStripe + 8*6);
                final long data_val_1 = access.i64(input, offStripe + 8*7);
                final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*6);
                final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*7);
                /* swap adjacent lanes */
                acc_6 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                acc_7 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
            }
        }

        /* last stripe */
        // XXH3_accumulate_512
        final long offStripe = off + length - 64;
        final long offSec = 192 - 64 - 7;
        {
            final long data_val_0 = access.i64(input, offStripe + 8*0);
            final long data_val_1 = access.i64(input, offStripe + 8*1);
            final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*0);
            final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*1);
            /* swap adjacent lanes */
            acc_0 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_1 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = access.i64(input, offStripe + 8*2);
            final long data_val_1 = access.i64(input, offStripe + 8*3);
            final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*2);
            final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*3);
            /* swap adjacent lanes */
            acc_2 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_3 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = access.i64(input, offStripe + 8*4);
            final long data_val_1 = access.i64(input, offStripe + 8*5);
            final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*4);
            final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*5);
            /* swap adjacent lanes */
            acc_4 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_5 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = access.i64(input, offStripe + 8*6);
            final long data_val_1 = access.i64(input, offStripe + 8*7);
            final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*6);
            final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*7);
            /* swap adjacent lanes */
            acc_6 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_7 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }

        // XXH3_mergeAccs
        final long result64 = length * XXH_PRIME64_1
                + XXH3_mix2Accs(acc_0, acc_1, secret, BYTE_BASE + 11)
                + XXH3_mix2Accs(acc_2, acc_3, secret, BYTE_BASE + 11 + 16)
                + XXH3_mix2Accs(acc_4, acc_5, secret, BYTE_BASE + 11 + 16 * 2)
                + XXH3_mix2Accs(acc_6, acc_7, secret, BYTE_BASE + 11 + 16 * 3);

        return XXH3_avalanche(result64);
    }

    private static <T> void XXH3_128bits_internal(final long seed, final byte[] secret, final T input, final Access<T> access, final long off, final long length, final long[] result) {
        if (length <= 16) {
            // XXH3_len_0to16_128b
            if (length > 8) {
                // XXH3_len_9to16_128b
                final long bitflipl = (unsafeLE.i64(XXH3_kSecret, 32+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 40+BYTE_BASE)) - seed;
                final long bitfliph = (unsafeLE.i64(XXH3_kSecret, 48+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 56+BYTE_BASE)) + seed;
                long input_hi = access.i64(input, off + length - 8);
                final long input_lo = access.i64(input, off) ^ input_hi ^ bitflipl;
                long m128_lo = input_lo * XXH_PRIME64_1;
                long m128_hi = Maths.unsignedLongMulHigh(input_lo, XXH_PRIME64_1);
                m128_lo += (length - 1) << 54;
                input_hi ^= bitfliph;
                m128_hi += input_hi + Primitives.unsignedInt((int)input_hi) * (XXH_PRIME32_2 - 1);
                m128_lo ^= Long.reverseBytes(m128_hi);

                result[0] = XXH3_avalanche(m128_lo * XXH_PRIME64_2);
                result[1] = XXH3_avalanche(Maths.unsignedLongMulHigh(m128_lo, XXH_PRIME64_2) + m128_hi * XXH_PRIME64_2);
                return;
            }
            if (length >= 4) {
                // XXH3_len_4to8_128b
                long s = seed ^ Long.reverseBytes(seed & 0xFFFFFFFFL);
                final long input_lo = access.u32(input, off);
                final long input_hi = (long)access.i32(input, off + length - 4); // high int will be shifted

                final long bitflip = (unsafeLE.i64(XXH3_kSecret, 16+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 24+BYTE_BASE)) + s;
                final long keyed = (input_lo + (input_hi << 32)) ^ bitflip;
                final long pl = XXH_PRIME64_1 + (length << 2); /* Shift len to the left to ensure it is even, this avoids even multiplies. */
                long m128_lo = keyed * pl;
                long m128_hi = Maths.unsignedLongMulHigh(keyed, pl);
                m128_hi += (m128_lo << 1);
                m128_lo ^= (m128_hi >>> 3);

                m128_lo ^= m128_lo >>> 35;
                m128_lo *= 0x9FB21C651E98DF25L;
                m128_lo ^= m128_lo >>> 28;
                result[0] = m128_lo;
                result[1] = XXH3_avalanche(m128_hi);
                return;
            }
            if (length != 0) {
                // XXH3_len_1to3_128b
                final int c1 = access.u8(input, off + 0);
                final int c2 = access.i8(input, off + (length >> 1)); // high 3 bytes will be shifted
                final int c3 = access.u8(input, off + length - 1);
                final int combinedl = (c1 << 16) | (c2  << 24) | c3 | ((int)length << 8);
                final int combinedh = Integer.rotateLeft(Integer.reverseBytes(combinedl), 13);
                final long bitflipl = Primitives.unsignedInt(unsafeLE.i32(XXH3_kSecret, BYTE_BASE) ^ unsafeLE.i32(XXH3_kSecret, BYTE_BASE+4)) + seed;
                final long bitfliph = Primitives.unsignedInt(unsafeLE.i32(XXH3_kSecret, BYTE_BASE+8) ^ unsafeLE.i32(XXH3_kSecret, BYTE_BASE+12)) - seed;
                result[0] = XXH64_avalanche(Primitives.unsignedInt(combinedl) ^ bitflipl);
                result[1] = XXH64_avalanche(Primitives.unsignedInt(combinedh) ^ bitfliph);
                return;
            }
            result[0] = XXH64_avalanche(seed ^ unsafeLE.i64(XXH3_kSecret, BYTE_BASE+64) ^ unsafeLE.i64(XXH3_kSecret, BYTE_BASE+72));
            result[1] = XXH64_avalanche(seed ^ unsafeLE.i64(XXH3_kSecret, BYTE_BASE+80) ^ unsafeLE.i64(XXH3_kSecret, BYTE_BASE+88));
            return;
        }
        if (length <= 128) {
            // XXH3_len_17to128_128b
            result[0] = length * XXH_PRIME64_1;
            result[1] = 0;
            if (length > 32) {
                if (length > 64) {
                    if (length > 96) {
                        XXH128_mix32B(seed, input, access, off + 48, off + length - 64, BYTE_BASE + 96, result);
                    }
                    XXH128_mix32B(seed, input, access, off + 32, off + length - 48, BYTE_BASE + 64, result);
                }
                XXH128_mix32B(seed, input, access, off + 16, off + length - 32, BYTE_BASE + 32, result);
            }
            XXH128_mix32B(seed, input, access, off + 0, off + length - 16, BYTE_BASE, result);

            final long acc_lo = result[0];
            final long acc_hi = result[1];
            result[0] = XXH3_avalanche(acc_lo + acc_hi);
            result[1] = -XXH3_avalanche(acc_lo*XXH_PRIME64_1 + acc_hi*XXH_PRIME64_4 + (length - seed)*XXH_PRIME64_2);
            return;
        }

        if (length <= 240) {
            // XXH3_len_129to240_128b
            final int nbRounds = (int)length / 32;
            result[0] = length * XXH_PRIME64_1;
            result[1] = 0;
            int i = 0;
            for (; i < 4; ++i) {
                XXH128_mix32B(seed, input, access, off + 32*i, off + 32*i + 16, BYTE_BASE + 32*i, result);
            }
            result[0] = XXH3_avalanche(result[0]);
            result[1] = XXH3_avalanche(result[1]);

            for (; i < nbRounds; ++i) {
                XXH128_mix32B(seed, input, access, off + 32*i, off + 32*i + 16, BYTE_BASE + 3 + 32*(i-4), result);
            }

            /* last bytes */
            XXH128_mix32B(-seed, input, access, off + length - 16, off + length - 32, BYTE_BASE + 136 - 17 - 16, result);
            final long acc_lo = result[0];
            final long acc_hi = result[1];
            result[0] = XXH3_avalanche(acc_lo + acc_hi);
            result[1] = -XXH3_avalanche(acc_lo*XXH_PRIME64_1 + acc_hi*XXH_PRIME64_4 + (length - seed)*XXH_PRIME64_2);
            return;
        }

        // XXH3_hashLong_128b_internal
        long acc_0 = XXH_PRIME32_3;
        long acc_1 = XXH_PRIME64_1;
        long acc_2 = XXH_PRIME64_2;
        long acc_3 = XXH_PRIME64_3;
        long acc_4 = XXH_PRIME64_4;
        long acc_5 = XXH_PRIME32_2;
        long acc_6 = XXH_PRIME64_5;
        long acc_7 = XXH_PRIME32_1;

        // XXH3_hashLong_internal_loop
        final long nb_blocks = (length - 1) / block_len;
        for (long n = 0; n < nb_blocks; n++) {
            // XXH3_accumulate
            final long offBlock = off + n * block_len;
            for (long s = 0; s < nbStripesPerBlock; s++ ) {
                // XXH3_accumulate_512
                final long offStripe = offBlock + s * 64;
                final long offSec = s * 8;
                {
                    final long data_val_0 = access.i64(input, offStripe + 8*0);
                    final long data_val_1 = access.i64(input, offStripe + 8*1);
                    final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*0);
                    final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*1);
                    /* swap adjacent lanes */
                    acc_0 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                    acc_1 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
                }
                {
                    final long data_val_0 = access.i64(input, offStripe + 8*2);
                    final long data_val_1 = access.i64(input, offStripe + 8*3);
                    final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*2);
                    final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*3);
                    /* swap adjacent lanes */
                    acc_2 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                    acc_3 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
                }
                {
                    final long data_val_0 = access.i64(input, offStripe + 8*4);
                    final long data_val_1 = access.i64(input, offStripe + 8*5);
                    final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*4);
                    final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*5);
                    /* swap adjacent lanes */
                    acc_4 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                    acc_5 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
                }
                {
                    final long data_val_0 = access.i64(input, offStripe + 8*6);
                    final long data_val_1 = access.i64(input, offStripe + 8*7);
                    final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*6);
                    final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*7);
                    /* swap adjacent lanes */
                    acc_6 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                    acc_7 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
                }
            }

            // XXH3_scrambleAcc_scalar
            final long offSec = BYTE_BASE + 192 - 64;
            acc_0 = (acc_0 ^ (acc_0 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*0)) * XXH_PRIME32_1;
            acc_1 = (acc_1 ^ (acc_1 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*1)) * XXH_PRIME32_1;
            acc_2 = (acc_2 ^ (acc_2 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*2)) * XXH_PRIME32_1;
            acc_3 = (acc_3 ^ (acc_3 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*3)) * XXH_PRIME32_1;
            acc_4 = (acc_4 ^ (acc_4 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*4)) * XXH_PRIME32_1;
            acc_5 = (acc_5 ^ (acc_5 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*5)) * XXH_PRIME32_1;
            acc_6 = (acc_6 ^ (acc_6 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*6)) * XXH_PRIME32_1;
            acc_7 = (acc_7 ^ (acc_7 >>> 47) ^ unsafeLE.i64(secret, offSec + 8*7)) * XXH_PRIME32_1;
        }

        /* last partial block */
        final long nbStripes = ((length - 1) - (block_len * nb_blocks)) / 64;
        final long offBlock = off + block_len * nb_blocks;
        for (long s = 0; s < nbStripes; s++) {
            // XXH3_accumulate_512
            final long offStripe = offBlock + s * 64;
            final long offSec = s * 8;
            {
                final long data_val_0 = access.i64(input, offStripe + 8*0);
                final long data_val_1 = access.i64(input, offStripe + 8*1);
                final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*0);
                final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*1);
                /* swap adjacent lanes */
                acc_0 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                acc_1 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
            }
            {
                final long data_val_0 = access.i64(input, offStripe + 8*2);
                final long data_val_1 = access.i64(input, offStripe + 8*3);
                final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*2);
                final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*3);
                /* swap adjacent lanes */
                acc_2 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                acc_3 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
            }
            {
                final long data_val_0 = access.i64(input, offStripe + 8*4);
                final long data_val_1 = access.i64(input, offStripe + 8*5);
                final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*4);
                final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*5);
                /* swap adjacent lanes */
                acc_4 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                acc_5 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
            }
            {
                final long data_val_0 = access.i64(input, offStripe + 8*6);
                final long data_val_1 = access.i64(input, offStripe + 8*7);
                final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*6);
                final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*7);
                /* swap adjacent lanes */
                acc_6 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
                acc_7 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
            }
        }

        /* last stripe */
        // XXH3_accumulate_512
        final long offStripe = off + length - 64;
        final long offSec = 192 - 64 - 7;
        {
            final long data_val_0 = access.i64(input, offStripe + 8*0);
            final long data_val_1 = access.i64(input, offStripe + 8*1);
            final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*0);
            final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*1);
            /* swap adjacent lanes */
            acc_0 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_1 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = access.i64(input, offStripe + 8*2);
            final long data_val_1 = access.i64(input, offStripe + 8*3);
            final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*2);
            final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*3);
            /* swap adjacent lanes */
            acc_2 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_3 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = access.i64(input, offStripe + 8*4);
            final long data_val_1 = access.i64(input, offStripe + 8*5);
            final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*4);
            final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*5);
            /* swap adjacent lanes */
            acc_4 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_5 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }
        {
            final long data_val_0 = access.i64(input, offStripe + 8*6);
            final long data_val_1 = access.i64(input, offStripe + 8*7);
            final long data_key_0 = data_val_0 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*6);
            final long data_key_1 = data_val_1 ^ unsafeLE.i64(secret, BYTE_BASE + offSec + 8*7);
            /* swap adjacent lanes */
            acc_6 += data_val_1 + (0xFFFFFFFFL & data_key_0) * (data_key_0 >>> 32);
            acc_7 += data_val_0 + (0xFFFFFFFFL & data_key_1) * (data_key_1 >>> 32);
        }

        // XXH3_mergeAccs
        result[0] = XXH3_avalanche(length * XXH_PRIME64_1
                + XXH3_mix2Accs(acc_0, acc_1, secret, BYTE_BASE + 11)
                + XXH3_mix2Accs(acc_2, acc_3, secret, BYTE_BASE + 11 + 16)
                + XXH3_mix2Accs(acc_4, acc_5, secret, BYTE_BASE + 11 + 16 * 2)
                + XXH3_mix2Accs(acc_6, acc_7, secret, BYTE_BASE + 11 + 16 * 3));
        result[1] = XXH3_avalanche(~(length * XXH_PRIME64_2)
                + XXH3_mix2Accs(acc_0, acc_1, secret, BYTE_BASE + 192 - 64 - 11)
                + XXH3_mix2Accs(acc_2, acc_3, secret, BYTE_BASE + 192 - 64 - 11 + 16)
                + XXH3_mix2Accs(acc_4, acc_5, secret, BYTE_BASE + 192 - 64 - 11 + 16 * 2)
                + XXH3_mix2Accs(acc_6, acc_7, secret, BYTE_BASE + 192 - 64 - 11 + 16 * 3));
    }

    private static void XXH3_initCustomSecret(final byte[] customSecret, final long seed64) {
        final int nbRounds = 192 / 16;
        final ByteBuffer bb = ByteBuffer.wrap(customSecret).order(LITTLE_ENDIAN);
        for (int i=0; i < nbRounds; i++) {
            final long lo = unsafeLE.i64(XXH3_kSecret, BYTE_BASE + 16*i)     + seed64;
            final long hi = unsafeLE.i64(XXH3_kSecret, BYTE_BASE + 16*i + 8) - seed64;
            bb.putLong(16 * i + 0, lo);
            bb.putLong(16 * i + 8, hi);
        }
    }

    static LongHashFunction asLongHashFunctionWithoutSeed() {
        return AsLongHashFunction.SEEDLESS_INSTANCE;
    }

    private static class AsLongHashFunction extends LongHashFunction {
        private static final long serialVersionUID = 0L;
        private static final AsLongHashFunction SEEDLESS_INSTANCE = new AsLongHashFunction();

        public long seed() {
            return 0L;
        }

        @Override
        public long hashLong(long input) {
            input = Primitives.nativeToLittleEndian(input);
            final long s = seed() ^ Long.reverseBytes(seed() & 0xFFFFFFFFL);
            final long bitflip = (unsafeLE.i64(XXH3.XXH3_kSecret, 8+BYTE_BASE) ^ unsafeLE.i64(XXH3.XXH3_kSecret, 16+BYTE_BASE)) - s;
            final long keyed = Long.rotateLeft(input, 32) ^ bitflip;
            return XXH3_rrmxmx(keyed, 8);
        }

        @Override
        public long hashInt(int input) {
            input = Primitives.nativeToLittleEndian(input);
            long s = seed() ^ Long.reverseBytes(seed() & 0xFFFFFFFFL);
            final long bitflip = (unsafeLE.i64(XXH3.XXH3_kSecret, 8+BYTE_BASE) ^ unsafeLE.i64(XXH3.XXH3_kSecret, 16+BYTE_BASE)) - s;
            final long keyed = (Primitives.unsignedInt(input) + (((long)input) << 32)) ^ bitflip;
            return XXH3_rrmxmx(keyed, 4);
        }

        @Override
        public long hashShort(short input) {
            input = Primitives.nativeToLittleEndian(input);
            final int c1 = Primitives.unsignedByte((byte)input);
            final int c2 = Primitives.unsignedShort(input) >>> 8;
            final int c3 = c2;
            final long combined = Primitives.unsignedInt((c1 << 16) | (c2 << 24) | c3 | (2 << 8));
            final long bitflip = (unsafeLE.u32(XXH3.XXH3_kSecret, BYTE_BASE) ^ unsafeLE.u32(XXH3.XXH3_kSecret, 4+BYTE_BASE)) + seed();
            return XXH64_avalanche(combined ^ bitflip);
        }

        @Override
        public long hashChar(char input) {
            return hashShort((short) input);
        }

        @Override
        public long hashByte(byte input) {
            final int c1 = Primitives.unsignedByte(input);
            final int c2 = c1;
            final int c3 = c1;
            final long combined = Primitives.unsignedInt((c1 << 16) | (c2 << 24) | c3 | (1 << 8));
            final long bitflip = (unsafeLE.u32(XXH3.XXH3_kSecret, BYTE_BASE) ^ unsafeLE.u32(XXH3.XXH3_kSecret, 4+BYTE_BASE)) + seed();
            return XXH64_avalanche(combined ^ bitflip);
        }

        @Override
        public long hashVoid() {
            return XXH64_avalanche(seed() ^ unsafeLE.i64(XXH3.XXH3_kSecret, 56+BYTE_BASE) ^ unsafeLE.i64(XXH3.XXH3_kSecret, 64+BYTE_BASE));
        }

        @Override
        public <T> long hash(final T input, final Access<T> access, final long off, final long len) {
            return XXH3.XXH3_64bits_internal(0, XXH3.XXH3_kSecret, input, access.byteOrder(input, LITTLE_ENDIAN), off, len);
        }
    }

    static LongHashFunction asLongHashFunctionWithSeed(final long seed) {
        return 0 == seed ? AsLongHashFunction.SEEDLESS_INSTANCE : new AsLongHashFunctionSeeded(seed);
    }

    private static class AsLongHashFunctionSeeded extends AsLongHashFunction {
        private static final long serialVersionUID = 0L;

        private final long seed;
        private final byte[] secret = new byte[192];

        private AsLongHashFunctionSeeded(final long seed) {
            this.seed = seed;
            XXH3_initCustomSecret(this.secret, seed);
        }

        @Override
        public long seed() {
            return seed;
        }

        @Override
        public <T> long hash(final T input, final Access<T> access, final long off, final long len) {
            return XXH3.XXH3_64bits_internal(this.seed, this.secret, input, access.byteOrder(input, LITTLE_ENDIAN), off, len);
        }
    }

    static LongTupleHashFunction asLongTupleHashFunctionWithoutSeed() {
        return AsLongTupleHashFunction.SEEDLESS_INSTANCE;
    }

    private static class AsLongTupleHashFunction extends DualHashFunction {
        private static final long serialVersionUID = 0L;
        private static final AsLongTupleHashFunction SEEDLESS_INSTANCE = new AsLongTupleHashFunction();

        public long seed() {
            return 0L;
        }

        @Override
        public int bitsLength() {
            return 128;
        }

        @Override
        public long[] newResultArray() {
            return new long[2]; // override for a little performance
        }

        @Override
        public long dualHashLong(long input, final long[] result) {
            input = Primitives.nativeToLittleEndian(input);
            long s = seed() ^ Long.reverseBytes(seed() & 0xFFFFFFFFL);
            final long bitflip = (unsafeLE.i64(XXH3_kSecret, 16+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 24+BYTE_BASE)) + s;
            final long keyed = input ^ bitflip;
            final long pl = XXH_PRIME64_1 + (8 << 2); /* Shift len to the left to ensure it is even, this avoids even multiplies. */
            long m128_lo = keyed * pl;
            long m128_hi = Maths.unsignedLongMulHigh(keyed, pl);
            m128_hi += (m128_lo << 1);
            m128_lo ^= (m128_hi >>> 3);

            m128_lo ^= m128_lo >>> 35;
            m128_lo *= 0x9FB21C651E98DF25L;
            m128_lo ^= m128_lo >>> 28;
            result[0] = m128_lo;
            result[1] = XXH3_avalanche(m128_hi);
            return m128_lo;
        }

        @Override
        public long dualHashInt(final int input, final long[] result) {
            final long inputU = Primitives.unsignedInt(Primitives.nativeToLittleEndian(input));
            long s = seed() ^ Long.reverseBytes(seed() & 0xFFFFFFFFL);
            final long bitflip = (unsafeLE.i64(XXH3_kSecret, 16+BYTE_BASE) ^ unsafeLE.i64(XXH3_kSecret, 24+BYTE_BASE)) + s;
            final long keyed = (inputU + (inputU << 32)) ^ bitflip;
            final long pl = XXH_PRIME64_1 + (4 << 2); /* Shift len to the left to ensure it is even, this avoids even multiplies. */
            long m128_lo = keyed * pl;
            long m128_hi = Maths.unsignedLongMulHigh(keyed, pl);

            m128_hi += (m128_lo << 1);
            m128_lo ^= (m128_hi >>> 3);

            m128_lo ^= m128_lo >>> 35;
            m128_lo *= 0x9FB21C651E98DF25L;
            m128_lo ^= m128_lo >>> 28;
            result[0] = m128_lo;
            result[1] = XXH3_avalanche(m128_hi);
            return m128_lo;
        }

        @Override
        public long dualHashShort(short input, final long[] result) {
            input = Primitives.nativeToLittleEndian(input);
            final int c1 = Primitives.unsignedByte((byte)input);
            final int c2 = Primitives.unsignedShort(input) >>> 8;
            final int c3 = c2;
            final int combinedl = (c1 << 16) | (c2  << 24) | c3 | (2 << 8);
            final int combinedh = Integer.rotateLeft(Integer.reverseBytes(combinedl), 13);
            final long bitflipl = Primitives.unsignedInt(unsafeLE.i32(XXH3_kSecret, BYTE_BASE) ^ unsafeLE.i32(XXH3_kSecret, BYTE_BASE+4)) + seed();
            final long bitfliph = Primitives.unsignedInt(unsafeLE.i32(XXH3_kSecret, BYTE_BASE+8) ^ unsafeLE.i32(XXH3_kSecret, BYTE_BASE+12)) - seed();
            result[0] = XXH64_avalanche(Primitives.unsignedInt(combinedl) ^ bitflipl);
            result[1] = XXH64_avalanche(Primitives.unsignedInt(combinedh) ^ bitfliph);
            return result[0];
        }

        @Override
        public long dualHashChar(char input, final long[] result) {
            return dualHashShort((short) input, result);
        }

        @Override
        public long dualHashByte(byte input, final long[] result) {
            final int c1 = Primitives.unsignedByte(input);
            //final int c2 = c1;
            final int c2 = (byte)input;
            final int c3 = c1;
            final int combinedl = (c1 << 16) | (c2  << 24) | c3 | (1 << 8);
            final int combinedh = Integer.rotateLeft(Integer.reverseBytes(combinedl), 13);
            final long bitflipl = Primitives.unsignedInt(unsafeLE.i32(XXH3_kSecret, BYTE_BASE) ^ unsafeLE.i32(XXH3_kSecret, BYTE_BASE+4)) + seed();
            final long bitfliph = Primitives.unsignedInt(unsafeLE.i32(XXH3_kSecret, BYTE_BASE+8) ^ unsafeLE.i32(XXH3_kSecret, BYTE_BASE+12)) - seed();
            result[0] = XXH64_avalanche(Primitives.unsignedInt(combinedl) ^ bitflipl);
            result[1] = XXH64_avalanche(Primitives.unsignedInt(combinedh) ^ bitfliph);
            return result[0];
        }

        @Override
        public long dualHashVoid(final long[] result) {
            result[0] = XXH64_avalanche(seed() ^ unsafeLE.i64(XXH3_kSecret, BYTE_BASE+64) ^ unsafeLE.i64(XXH3_kSecret, BYTE_BASE+72));
            result[1] = XXH64_avalanche(seed() ^ unsafeLE.i64(XXH3_kSecret, BYTE_BASE+80) ^ unsafeLE.i64(XXH3_kSecret, BYTE_BASE+88));
            return result[0];
        }

        @Override
        public <T> long dualHash(final T input, final Access<T> access, final long off, final long len, final long[] result) {
            XXH3.XXH3_128bits_internal(0, XXH3.XXH3_kSecret, input, access.byteOrder(input, LITTLE_ENDIAN), off, len, result);
            return result[0];
        }
    }

    static LongTupleHashFunction asLongTupleHashFunctionWithSeed(final long seed) {
        return 0 == seed ? AsLongTupleHashFunction.SEEDLESS_INSTANCE : new AsLongTupleHashFunctionSeeded(seed);
    }

    private static class AsLongTupleHashFunctionSeeded extends AsLongTupleHashFunction {
        private static final long serialVersionUID = 0L;

        private final long seed;
        private final byte[] secret = new byte[192];

        private AsLongTupleHashFunctionSeeded(final long seed) {
            this.seed = seed;
            XXH3_initCustomSecret(this.secret, seed);
        }

        @Override
        public long seed() {
            return seed;
        }

        @Override
        public <T> long dualHash(final T input, final Access<T> access, final long off, final long len, final long[] result) {
            XXH3.XXH3_128bits_internal(this.seed, this.secret, input, access.byteOrder(input, LITTLE_ENDIAN), off, len, result);
            return result[0];
        }
    }
}

/*
 * Copyright 2014 Higher Frequency Trading http://www.higherfrequencytrading.com
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

import static java.lang.Long.reverseBytes;
import static java.lang.Long.rotateRight;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static net.openhft.hashing.LongHashFunction.NATIVE_LITTLE_ENDIAN;

/**
 * Adapted from the C++ CityHash implementation from Google at
 * http://code.google.com/p/cityhash/source/browse/trunk/src/city.cc.
 */
class CityAndFarmHash_1_1 {
    private static final CityAndFarmHash_1_1 INSTANCE = new CityAndFarmHash_1_1();

    static final CityAndFarmHash_1_1 NATIVE_CITY = NATIVE_LITTLE_ENDIAN ?
            CityAndFarmHash_1_1.INSTANCE : BigEndian.INSTANCE;

    CityAndFarmHash_1_1() {}

    static final long K0 = 0xc3a5c85c97cb3127L;
    static final long K1 = 0xb492b66fbe98f273L;
    static final long K2 = 0x9ae16a3b2f90404fL;

    static long shiftMix(long val) {
        return val ^ (val >>> 47);
    }

    static long hashLen16(long u, long v) {
        return hashLen16(u, v, K_MUL);
    }

    private static final long K_MUL = 0x9ddfea08eb382d69L;

    static long hashLen16(long u, long v, long mul) {
        long a = shiftMix((u ^ v) * mul);
        return shiftMix((v ^ a) * mul) * mul;
    }

    static long mul(long len) {
        return K2 + (len << 1);
    }

    static long hash1To3Bytes(int len, int firstByte, int midOrLastByte, int lastByte) {
        int y = firstByte + (midOrLastByte << 8);
        int z = len + (lastByte << 2);
        return shiftMix((((long) y) * K2) ^ (((long) z) * K0)) * K2;
    }

    static long hash4To7Bytes(long len, long first4Bytes, long last4Bytes) {
        long mul = mul(len);
        return hashLen16(len + (first4Bytes << 3), last4Bytes, mul);
    }

    static long hash8To16Bytes(long len, long first8Bytes, long last8Bytes) {
        long mul = mul(len);
        long a = first8Bytes + K2;
        long c = rotateRight(last8Bytes, 37) * mul + a;
        long d = (rotateRight(a, 25) + last8Bytes) * mul;
        return hashLen16(c, d, mul);
    }

    <T> long fetch64(Access<T> access, T in, long off) {
        return access.getLong(in, off);
    }

    <T> int fetch32(Access<T> access, T in, long off) {
        return access.getInt(in, off);
    }

    long toLittleEndian(long v) {
        return v;
    }

    int toLittleEndian(int v) {
        return v;
    }

    <T> long hashLen0To16(Access<T> access, T in, long off, long len) {
        if (len >= 8L) {
            long a = fetch64(access, in, off);
            long b = fetch64(access, in, off + len - 8L);
            return hash8To16Bytes(len, a, b);
        } else if (len >= 4L) {
            long a = Primitives.unsignedInt(fetch32(access, in, off));
            long b = Primitives.unsignedInt(fetch32(access, in, off + len - 4L));
            return hash4To7Bytes(len, a, b);
        } else if (len > 0L) {
            int a = access.getUnsignedByte(in, off);
            int b = access.getUnsignedByte(in, off + (len >> 1));
            int c = access.getUnsignedByte(in, off + len - 1L);
            return hash1To3Bytes((int) len, a, b, c);
        }
        return K2;
    }

    <T> long hashLen17To32(Access<T> access, T in, long off, long len) {
        long mul = mul(len);
        long a = fetch64(access, in, off) * K1;
        long b = fetch64(access, in, off + 8L);
        long c = fetch64(access, in, off + len - 8L) * mul;
        long d = fetch64(access, in, off + len - 16L) * K2;
        return hashLen16(rotateRight(a + b, 43) + rotateRight(c, 30) + d,
                a + rotateRight(b + K2, 18) + c, mul);
    }

    private <T> long cityHashLen33To64(Access<T> access, T in, long off, long len) {
        long mul = mul(len);
        long a = fetch64(access, in, off) * K2;
        long b = fetch64(access, in, off + 8L);
        long c = fetch64(access, in, off + len - 24L);
        long d = fetch64(access, in, off + len - 32L);
        long e = fetch64(access, in, off + 16L) * K2;
        long f = fetch64(access, in, off + 24L) * 9L;
        long g = fetch64(access, in, off + len - 8L);
        long h = fetch64(access, in, off + len - 16L) * mul;
        long u = rotateRight(a + g, 43) + (rotateRight(b, 30) + c) * 9L;
        long v = ((a + g) ^ d) + f + 1L;
        long w = reverseBytes((u + v) * mul) + h;
        long x = rotateRight(e + f, 42) + c;
        long y = (reverseBytes((v + w) * mul) + g) * mul;
        long z = e + f + c;
        a = reverseBytes((x + z) * mul + y) + b;
        b = shiftMix((z + a) * mul + d + h) * mul;
        return b + x;
    }

    <T> long cityHash64(Access<T> access, T in, long off, long len) {
        if (len <= 32L) {
            if (len <= 16L) {
                return hashLen0To16(access, in, off, len);
            } else {
                return hashLen17To32(access, in, off, len);
            }
        } else if (len <= 64L) {
            return cityHashLen33To64(access, in, off, len);
        }

        long x = fetch64(access, in, off + len - 40L);
        long y = fetch64(access, in, off + len - 16L) + fetch64(access, in, off + len - 56L);
        long z = hashLen16(fetch64(access, in, off + len - 48L) + len,
                fetch64(access, in, off + len - 24L));

        long vFirst, vSecond, wFirst, wSecond;

        // This and following 3 blocks are produced by a single-click inline-function refactoring.
        // IntelliJ IDEA ftw
        // WeakHashLen32WithSeeds
        long a3 = len;
        long b3 = z;
        long w4 = fetch64(access, in, off + len - 64L);
        long x4 = fetch64(access, in, off + len - 64L + 8L);
        long y4 = fetch64(access, in, off + len - 64L + 16L);
        long z4 = fetch64(access, in, off + len - 64L + 24L);
        a3 += w4;
        b3 = rotateRight(b3 + a3 + z4, 21);
        long c3 = a3;
        a3 += x4 + y4;
        b3 += rotateRight(a3, 44);
        vFirst = a3 + z4;
        vSecond = b3 + c3;

        // WeakHashLen32WithSeeds
        long a2 = y + K1;
        long b2 = x;
        long w3 = fetch64(access, in, off + len - 32L);
        long x3 = fetch64(access, in, off + len - 32L + 8L);
        long y3 = fetch64(access, in, off + len - 32L + 16L);
        long z3 = fetch64(access, in, off + len - 32L + 24L);
        a2 += w3;
        b2 = rotateRight(b2 + a2 + z3, 21);
        long c2 = a2;
        a2 += x3 + y3;
        b2 += rotateRight(a2, 44);
        wFirst = a2 + z3;
        wSecond = b2 + c2;

        x = x * K1 + fetch64(access, in, off);

        len = (len - 1L) & (~63L);
        do {
            x = rotateRight(x + y + vFirst + fetch64(access, in, off + 8L), 37) * K1;
            y = rotateRight(y + vSecond + fetch64(access, in, off + 48L), 42) * K1;
            x ^= wSecond;
            y += vFirst + fetch64(access, in, off + 40L);
            z = rotateRight(z + wFirst, 33) * K1;

            // WeakHashLen32WithSeeds
            long a1 = vSecond * K1;
            long b1 = x + wFirst;
            long w2 = fetch64(access, in, off);
            long x2 = fetch64(access, in, off + 8L);
            long y2 = fetch64(access, in, off + 16L);
            long z2 = fetch64(access, in, off + 24L);
            a1 += w2;
            b1 = rotateRight(b1 + a1 + z2, 21);
            long c1 = a1;
            a1 += x2 + y2;
            b1 += rotateRight(a1, 44);
            vFirst = a1 + z2;
            vSecond = b1 + c1;

            // WeakHashLen32WithSeeds
            long a = z + wSecond;
            long b = y + fetch64(access, in, off + 16L);
            long w1 = fetch64(access, in, off + 32L);
            long x1 = fetch64(access, in, off + 32L + 8L);
            long y1 = fetch64(access, in, off + 32L + 16L);
            long z1 = fetch64(access, in, off + 32L + 24L);
            a += w1;
            b = rotateRight(b + a + z1, 21);
            long c = a;
            a += x1 + y1;
            b += rotateRight(a, 44);
            wFirst = a + z1;
            wSecond = b + c;

            long tmp = x;
            x = z;
            z = tmp;

            len -= 64L;
            off += 64L;
        } while (len != 0);
        return hashLen16(hashLen16(vFirst, wFirst) + shiftMix(y) * K1 + z,
                hashLen16(vSecond, wSecond) + x);
    }

    private static class BigEndian extends CityAndFarmHash_1_1 {
        private static final BigEndian INSTANCE = new BigEndian();
        private BigEndian() {}

        @Override
        <T> long fetch64(Access<T> access, T in, long off) {
            return reverseBytes(super.fetch64(access, in, off));
        }

        @Override
        <T> int fetch32(Access<T> access, T in, long off) {
            return Integer.reverseBytes(super.fetch32(access, in, off));
        }

        @Override
        long toLittleEndian(long v) {
            return reverseBytes(v);
        }

        @Override
        int toLittleEndian(int v) {
            return Integer.reverseBytes(v);
        }
    }

    static class AsLongHashFunction extends LongHashFunction {
        public static final AsLongHashFunction INSTANCE = new AsLongHashFunction();
        private static final long serialVersionUID = 0L;

        private static Object readResolve() {
            return INSTANCE;
        }

        @Override
        public long hashLong(long input) {
            input = NATIVE_CITY.toLittleEndian(input);
            long hash = hash8To16Bytes(8L, input, input);
            return finalize(hash);
        }

        @Override
        public long hashInt(int input) {
            input = NATIVE_CITY.toLittleEndian(input);
            long unsignedInt = Primitives.unsignedInt(input);
            long hash = hash4To7Bytes(4L, unsignedInt, unsignedInt);
            return finalize(hash);
        }

        @Override
        public long hashShort(short input) {
            return hashChar((char) input);
        }

        private static final int FIRST_SHORT_BYTE_SHIFT = NATIVE_LITTLE_ENDIAN ? 0 : 8;
        // JIT could probably optimize & -1 to no-op
        private static final int FIRST_SHORT_BYTE_MASK = NATIVE_LITTLE_ENDIAN ? 0xFF : -1;
        private static final int SECOND_SHORT_BYTE_SHIFT = 8 - FIRST_SHORT_BYTE_SHIFT;
        private static final int SECOND_SHORT_BYTE_MASK = NATIVE_LITTLE_ENDIAN ? -1 : 0xFF;

        @Override
        public long hashChar(char input) {
            int unsignedInput = (int) input;
            int firstByte = (unsignedInput >> FIRST_SHORT_BYTE_SHIFT) & FIRST_SHORT_BYTE_MASK;
            int secondByte = (unsignedInput >> SECOND_SHORT_BYTE_SHIFT) & SECOND_SHORT_BYTE_MASK;
            long hash = hash1To3Bytes(2, firstByte, secondByte, secondByte);
            return finalize(hash);
        }

        @Override
        public long hashByte(byte input) {
            int unsignedByte = Primitives.unsignedByte(input);
            long hash = hash1To3Bytes(1, unsignedByte, unsignedByte, unsignedByte);
            return finalize(hash);
        }

        @Override
        public long hashVoid() {
            return K2;
        }

        @Override
        public <T> long hash(T input, Access<T> access, long off, long len) {
            long hash;
            if (access.byteOrder(input) == LITTLE_ENDIAN) {
                hash = CityAndFarmHash_1_1.INSTANCE.cityHash64(access, input, off, len);
            } else {
                hash = BigEndian.INSTANCE.cityHash64(access, input, off, len);
            }
            return finalize(hash);
        }

        long finalize(long hash) {
            return hash;
        }
    }

    public static LongHashFunction asLongHashFunctionWithoutSeed() {
        return AsLongHashFunction.INSTANCE;
    }

    private static class AsLongHashFunctionSeeded extends AsLongHashFunction {
        private static final long serialVersionUID = 0L;

        final long seed0, seed1;
        private transient long voidHash;

        private AsLongHashFunctionSeeded(long seed0, long seed1) {
            this.seed0 = seed0;
            this.seed1 = seed1;
            voidHash = finalize(K2);
        }

        @Override
        public long hashVoid() {
            return voidHash;
        }

        @Override
        protected long finalize(long hash) {
            return hashLen16(hash - seed0, seed1);
        }
    }

    public static LongHashFunction asLongHashFunctionWithSeed(long seed) {
        return new AsLongHashFunctionSeeded(K2, seed);
    }

    public static LongHashFunction asLongHashFunctionWithTwoSeeds(long seed0, long seed1) {
        return new AsLongHashFunctionSeeded(seed0, seed1);
    }


    // FarmHash

    private <T> long naHashLen33To64(Access<T> access, T in, long off, long len) {
        long mul = mul(len);
        long a = fetch64(access, in, off) * K2;
        long b = fetch64(access, in, off + 8L);
        long c = fetch64(access, in, off + len - 8) * mul;
        long d = fetch64(access, in, off + len - 16) * K2;
        long y = rotateRight(a + b, 43) + rotateRight(c, 30) + d;
        long z = hashLen16(y, a + rotateRight(b + K2, 18) + c, mul);
        long e = fetch64(access, in, off + 16) * mul;
        long f = fetch64(access, in, off + 24);
        long g = (y + fetch64(access, in, off + len - 32)) * mul;
        long h = (z + fetch64(access, in, off + len - 24)) * mul;
        return hashLen16(rotateRight(e + f, 43) + rotateRight(g, 30) + h,
                e + rotateRight(f + a, 18) + g, mul);
    }

    <T> long naHash64(Access<T> access, T in, long off, long len) {
        final long seed = 81;
        if (len <= 32) {
            if (len <= 16) {
                return hashLen0To16(access, in, off, len);
            } else {
                return hashLen17To32(access, in, off, len);
            }
        } else if (len <= 64) {
            return naHashLen33To64(access, in, off, len);
        }

        // For strings over 64 bytes we loop.  Internal state consists of
        // 56 bytes: v, w, x, y, and z.
        long x = seed;
        // == seed * k1 + 113; This overflows uint64 and is a compile error,
        // so we expand the constant by hand
        @SuppressWarnings("NumericOverflow")
        long y = seed * K1 + 113;
        long z = shiftMix(y * K2 + 113) * K2;
        long v1 = 0, v2 = 0;
        long w1 = 0, w2 = 0;
        x = x * K2 + fetch64(access, in, off);

        // Set end so that after the loop we have 1 to 64 bytes left to process.
        long end = off + ((len - 1) >> 6) * 64;
        long last64 = end + ((len - 1) & 63) - 63;

        do {
            x = rotateRight(x + y + v1 + fetch64(access, in, off + 8), 37) * K1;
            y = rotateRight(y + v2 + fetch64(access, in, off + 48), 42) * K1;
            x ^= w2;
            y += v1 + fetch64(access, in, off + 40);
            z = rotateRight(z + w1, 33) * K1;
            long a = v2 * K1;
            long b = x + w1;
            long z1 = fetch64(access, in, off + 24);
            a += fetch64(access, in, off);
            b = rotateRight(b + a + z1, 21);
            long c = a;
            a += fetch64(access, in, off + 8);
            a += fetch64(access, in, off + 16);
            b += rotateRight(a, 44);
            v1 = a + z1;
            v2 = b + c;
            long a1 = z + w2;
            long b1 = y + fetch64(access, in, off + 16);
            long z2 = fetch64(access, in, off + 32 + 24);
            a1 += fetch64(access, in, off + 32);
            b1 = rotateRight(b1 + a1 + z2, 21);
            long c1 = a1;
            a1 += fetch64(access, in, off + 32 + 8);
            a1 += fetch64(access, in, off + 32 + 16);
            b1 += rotateRight(a1, 44);
            w1 = a1 + z2;
            w2 = b1 + c1;
            long t = z;
            z = x;
            x = t;
        } while ((off += 64) != end);

        off = last64;

        long mul = K1 + ((z & 0xff) << 1);

        // Make s point to the last 64 bytes of input.
        w1 += (len - 1) & 63;
        v1 += w1;
        w1 += v1;
        x = rotateRight(x + y + v1 + fetch64(access, in, off + 8), 37) * mul;
        y = rotateRight(y + v2 + fetch64(access, in, off + 48), 42) * mul;
        x ^= w2 * 9;
        y += v1 * 9 + fetch64(access, in, off + 40);
        z = rotateRight(z + w1, 33) * mul;
        long a = v2 * mul;
        long b = x + w1;
        long z1 = fetch64(access, in, off + 24);
        a += fetch64(access, in, off);
        b = rotateRight(b + a + z1, 21);
        long c = a;
        a += fetch64(access, in, off + 8);
        a += fetch64(access, in, off + 16);
        b += rotateRight(a, 44);
        v1 = a + z1;
        v2 = b + c;
        long a1 = z + w2;
        long b1 = y + fetch64(access, in, off + 16);
        long z2 = fetch64(access, in, off + 32 + 24);
        a1 += fetch64(access, in, off + 32);
        b1 = rotateRight(b1 + a1 + z2, 21);
        long c1 = a1;
        a1 += fetch64(access, in, off + 32 + 8);
        a1 += fetch64(access, in, off + 32 + 16);
        b1 += rotateRight(a1, 44);
        w1 = a1 + z2;
        w2 = b1 + c1;
        long t = z;
        z = x;
        x = t;
        return hashLen16(hashLen16(v1, w1, mul) + shiftMix(y) * K0 + z,
                hashLen16(v2, w2, mul) + x,
                mul);
    }

    <T> long naHash64WithSeeds(Access<T> access, T in, long off, long len, long seed0, long seed1) {
        return hashLen16(naHash64(access, in, off, len) - seed0, seed1);
    }

    long uoH(long x, long y, long mul, int r) {
        long a = (x ^ y) * mul;
        a = shiftMix(a);
        long b = (y ^ a) * mul;
        return rotateRight(b, r) * mul;
    }

    <T> long uoHash64WithSeeds(Access<T> access, T in, long off, long len, long seed0, long seed1) {
        if (len <= 64) {
            return naHash64WithSeeds(access, in, off, len, seed0, seed1);
        }

        long x = seed0;
        long y = seed1 * K2 + 113;
        long z = shiftMix(y * K2) * K2;
        long v0 = seed0;
        long v1 = seed1;
        long w0 = 0;
        long w1 = 0;
        long u = x - z;
        x *= K2;
        long mul = K2 + (u & 0x82);

        long end = off + ((len - 1) >> 6) * 64;
        long last64 = end + ((len - 1) & 63) - 63;

        do {
            long a0 = fetch64(access, in, off);
            long a1 = fetch64(access, in, off + 8);
            long a2 = fetch64(access, in, off + 16);
            long a3 = fetch64(access, in, off + 24);
            long a4 = fetch64(access, in, off + 32);
            long a5 = fetch64(access, in, off + 40);
            long a6 = fetch64(access, in, off + 48);
            long a7 = fetch64(access, in, off + 56);
            x += a0 + a1;
            y += a2;
            z += a3;
            v0 += a4;
            v1 += a5 + a1;
            w0 += a6;
            w1 += a7;

            x = rotateRight(x, 26);
            x *= 9;
            y = rotateRight(y, 29);
            z *= mul;
            v0 = rotateRight(v0, 33);
            v1 = rotateRight(v1, 30);
            w0 ^= x;
            w0 *= 9;
            z = rotateRight(z, 32);
            z += w1;
            w1 += z;
            z *= 9;

            long t = u;
            u = y;
            y = t;

            z += a0 + a6;
            v0 += a2;
            v1 += a3;
            w0 += a4;
            w1 += a5 + a6;
            x += a1;
            y += a7;

            y += v0;
            v0 += x - y;
            v1 += w0;
            w0 += v1;
            w1 += x - y;
            x += w1;
            w1 = rotateRight(w1, 34);

            t = u;
            u = z;
            z = t;

        } while ((off += 64) != end);

        off = last64;

        u *= 9;
        v1 = rotateRight(v1, 28);
        v0 = rotateRight(v0, 20);
        w0 += (len - 1) & 63;
        u += y;
        y += u;
        x = rotateRight(y - x + v0 + fetch64(access, in, off + 8), 37) * mul;
        y = rotateRight(y ^ v1 ^ fetch64(access, in, off + 48), 42) * mul;
        x ^= w1 * 9;
        y += v0 + fetch64(access, in, off + 40);
        z = rotateRight(z + w0, 33) * mul;

        long a = v1 * mul;
        long b = x + w0;
        long z1 = fetch64(access, in, off + 24);
        a += fetch64(access, in, off);
        b = rotateRight(b + a + z1, 21);
        long c = a;
        a += fetch64(access, in, off + 8);
        a += fetch64(access, in, off + 16);
        b += rotateRight(a, 44);
        v0 =  a + z1;
        v1 = b + c;

        long a1 = z + w1;
        long b1 = y + fetch64(access, in, off + 16);
        long z2 = fetch64(access, in, off + 32 + 24);
        a1 += fetch64(access, in, off + 32);
        b1 = rotateRight(b1 + a1 + z2, 21);
        long c1 = a1;
        a1 += fetch64(access, in, off + 32 + 8);
        a1 += fetch64(access, in, off + 32 + 16);
        b1 += rotateRight(a1, 44);
        w0 = a1 + z2;
        w1 = b1 + c1;
        return uoH(hashLen16(v0 + x, w0 ^ y, mul) + z - u,
                uoH(v1 + y, w1 + z, K2, 30) ^ x,
                K2,
                31);
    }

    private static class Na extends CityAndFarmHash_1_1.AsLongHashFunction {
        public static final Na INSTANCE = new Na();
        private static final long serialVersionUID = 0L;

        private static Object readResolve() {
            return INSTANCE;
        }

        @Override
        public <T> long hash(T input, Access<T> access, long off, long len) {
            long hash;
            if (access.byteOrder(input) == LITTLE_ENDIAN) {
                hash = CityAndFarmHash_1_1.INSTANCE.naHash64(access, input, off, len);
            } else {
                hash = BigEndian.INSTANCE.naHash64(access, input, off, len);
            }
            return finalize(hash);
        }
    }

    public static LongHashFunction naWithoutSeeds() {
        return Na.INSTANCE;
    }

    private static class NaSeeded extends Na {
        private static final long serialVersionUID = 0L;

        final long seed0, seed1;
        private transient long voidHash;

        private NaSeeded(long seed0, long seed1) {
            this.seed0 = seed0;
            this.seed1 = seed1;
            voidHash = finalize(K2);
        }

        @Override
        public long hashVoid() {
            return voidHash;
        }

        @Override
        protected long finalize(long hash) {
            return hashLen16(hash - seed0, seed1);
        }
    }

    public static LongHashFunction naWithSeed(long seed) {
        return new NaSeeded(K2, seed);
    }

    public static LongHashFunction naWithSeeds(long seed0, long seed1) {
        return new NaSeeded(seed0, seed1);
    }

    private static final class Uo extends AsLongHashFunction {
        public static final Uo INSTANCE = new Uo();
        private static final long serialVersionUID = 0L;

        private static Object readResolve() {
            return INSTANCE;
        }

        @Override
        public <T> long hash(T input, Access<T> access, long off, long len) {
            CityAndFarmHash_1_1 instance = access.byteOrder(input) == LITTLE_ENDIAN ?
                    CityAndFarmHash_1_1.INSTANCE : BigEndian.INSTANCE;
            if (len <= 64) {
                return instance.naHash64(access, input, off, len);
            }
            return instance.uoHash64WithSeeds(access, input, off, len, 81, 0);
        }
    }

    public static LongHashFunction uoWithoutSeeds() {
        return Uo.INSTANCE;
    }

    private final static class UoWithOneSeed extends AsLongHashFunctionSeeded {
        private static final long serialVersionUID = 0L;

        private UoWithOneSeed(long seed) {
            super(K2, seed);
        }

        @Override
        public <T> long hash(T input, Access<T> access, long off, long len) {
            CityAndFarmHash_1_1 instance = access.byteOrder(input) == LITTLE_ENDIAN ?
                    CityAndFarmHash_1_1.INSTANCE : BigEndian.INSTANCE;
            if (len <= 64) {
                return finalize(instance.naHash64(access, input, off, len));
            }
            return instance.uoHash64WithSeeds(access, input, off, len, 0, seed1);
        }
    }

    public static LongHashFunction uoWithSeed(long seed) {
        return new UoWithOneSeed(seed);
    }

    private static class UoSeeded extends AsLongHashFunctionSeeded {
        private static final long serialVersionUID = 0L;

        private UoSeeded(long seed0, long seed1) {
            super(seed0, seed1);
        }

        @Override
        public <T> long hash(T input, Access<T> access, long off, long len) {
            if (access.byteOrder(input) == LITTLE_ENDIAN) {
                return CityAndFarmHash_1_1.INSTANCE.uoHash64WithSeeds(
                        access, input, off, len, seed0, seed1);
            } else {
                return BigEndian.INSTANCE.uoHash64WithSeeds(access, input, off, len, seed0, seed1);
            }
        }
    }

    public static LongHashFunction uoWithSeeds(long seed0, long seed1) {
        return new UoSeeded(seed0, seed1);
    }
}

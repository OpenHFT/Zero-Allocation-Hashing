package net.openhft.hashing;

import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static net.openhft.hashing.LongHashFunction.NATIVE_LITTLE_ENDIAN;

class MetroHash {
    private static final MetroHash INSTANCE = new MetroHash();
    private static final MetroHash NATIVE_METRO = NATIVE_LITTLE_ENDIAN ?
            MetroHash.INSTANCE : BigEndian.INSTANCE;

    //primes
    private static final long k0 = 0xD6D018F5L;
    private static final long k1 = 0xA2AA033BL;
    private static final long k2 = 0x62992FC1L;
    private static final long k3 = 0x30BC5B29L;

    <T> long fetch64(Access<T> access, T in, long off) {
        return access.getLong(in, off);
    }

    <T> long fetch32(Access<T> access, T in, long off) {
        return access.getUnsignedInt(in, off);
    }

    <T> long fetch16(Access<T> access, T in, long off) {
        return access.getUnsignedShort(in, off);
    }

    <T> int fetch8(Access<T> access, T in, long off) {
        return access.getUnsignedByte(in, off);
    }

    long toLittleEndian(long v) {
        return v;
    }

    int toLittleEndian(int v) {
        return v;
    }

    short toLittleEndian(short v) {
        return v;
    }


    public <T> long metroHash64(long seed, T input, Access<T> access, long off, long length) {
        long remaining = length;

        long h = (seed + k2) * k0;

        if (length >= 32) {
            long v0 = h;
            long v1 = h;
            long v2 = h;
            long v3 = h;

            do {
                v0 += fetch64(access, input, off) * k0;
                v0 = Long.rotateRight(v0, 29) + v2;
                v1 += fetch64(access, input, off + 8) * k1;
                v1 = Long.rotateRight(v1, 29) + v3;
                v2 += fetch64(access, input, off + 16) * k2;
                v2 = Long.rotateRight(v2, 29) + v0;
                v3 += fetch64(access, input, off + 24) * k3;
                v3 = Long.rotateRight(v3, 29) + v1;

                off += 32;
                remaining -= 32;
            } while (remaining >= 32);

            v2 ^= Long.rotateRight(((v0 + v3) * k0) + v1, 37) * k1;
            v3 ^= Long.rotateRight(((v1 + v2) * k1) + v0, 37) * k0;
            v0 ^= Long.rotateRight(((v0 + v2) * k0) + v3, 37) * k1;
            v1 ^= Long.rotateRight(((v1 + v3) * k1) + v2, 37) * k0;

            h += v0 ^ v1;
        }

        if (remaining >= 16) {
            long v0 = h + (fetch64(access, input, off) * k2);
            v0 = Long.rotateRight(v0, 29) * k3;
            long v1 = h + (fetch64(access, input, off + 8) * k2);
            v1 = Long.rotateRight(v1, 29) * k3;
            v0 ^= Long.rotateRight(v0 * k0, 21) + v1;
            v1 ^= Long.rotateRight(v1 * k3, 21) + v0;
            h += v1;

            off += 16;
            remaining -= 16;
        }

        if (remaining >= 8) {
            h += fetch64(access, input, off) * k3;
            h ^= Long.rotateRight(h, 55) * k1;

            off += 8;
            remaining -= 8;
        }

        if (remaining >= 4) {
            h += fetch32(access, input, off) * k3;
            h ^= Long.rotateRight(h, 26) * k1;

            off += 4;
            remaining -= 4;
        }

        if (remaining >= 2) {
            h += fetch16(access, input, off) * k3;
            h ^= Long.rotateRight(h, 48) * k1;

            off += 2;
            remaining -= 2;
        }

        if (remaining >= 1) {
            h += fetch8(access, input, off) * k3;
            h ^= Long.rotateRight(h, 37) * k1;
        }

        return finalize(h);
    }

    private static long finalize(long h) {
        h ^= Long.rotateRight(h, 28);
        h *= k0;
        h ^= Long.rotateRight(h, 29);
        return h;
    }

    private static class BigEndian extends MetroHash {
        private static final BigEndian INSTANCE = new BigEndian();

        private BigEndian() {
        }

        @Override
        <T> long fetch64(Access<T> access, T in, long off) {
            return Long.reverseBytes(super.fetch64(access, in, off));
        }

        @Override
        <T> long fetch32(Access<T> access, T in, long off) {
            return Integer.reverseBytes(access.getInt(in, off)) & 0xFFFFFFFFL;
        }

        @Override
        <T> long fetch16(Access<T> access, T in, long off) {
            return Short.reverseBytes((short)access.getShort(in, off)) & 0xFFFFL;
        }

        @Override
        <T> int fetch8(Access<T> access, T in, long off) {
            return super.fetch8(access, in, off);
        }

        @Override
        long toLittleEndian(long v) {
            return Long.reverseBytes(v);
        }

        @Override
        int toLittleEndian(int v) {
            return Integer.reverseBytes(v);
        }

        @Override
        short toLittleEndian(short v) {
            return Short.reverseBytes(v);
        }
    }

    private static class AsLongHashFunction extends LongHashFunction {
        public static final AsLongHashFunction INSTANCE = new AsLongHashFunction();

        protected long seed() {
            return 0L;
        }

        @Override
        public long hashLong(long input) {
            input = NATIVE_METRO.toLittleEndian(input);
            long h = (seed() + k2) * k0;
            h += input * k3;
            h ^= Long.rotateRight(h, 55) * k1;

            return MetroHash.finalize(h);
        }

        @Override
        public long hashInt(int input) {
            input = NATIVE_METRO.toLittleEndian(input);
            long h = (seed() + k2) * k0;
            h += Primitives.unsignedInt(input) * k3;
            h ^= Long.rotateRight(h, 26) * k1;

            return MetroHash.finalize(h);
        }

        @Override
        public long hashShort(short input) {
            input = NATIVE_METRO.toLittleEndian(input);
            long h = (seed() + k2) * k0;
            h += Primitives.unsignedShort(input) * k3;
            h ^= Long.rotateRight(h, 48) * k1;

            return MetroHash.finalize(h);
        }

        @Override
        public long hashChar(char input) {
            return hashShort((short) input);
        }

        @Override
        public long hashByte(byte input) {
            long h = (seed() + k2) * k0;
            h += Primitives.unsignedByte(input) * k3;
            h ^= Long.rotateRight(h, 37) * k1;

            return MetroHash.finalize(h);
        }

        @Override
        public long hashVoid() {
            return MetroHash.finalize((seed() + k2) * k0);
        }

        @Override
        public <T> long hash(T input, Access<T> access, long off, long len) {
            long seed = seed();
            if (access.byteOrder(input) == LITTLE_ENDIAN) {
                return MetroHash.INSTANCE.metroHash64(seed, input, access, off, len);
            } else {
                return MetroHash.BigEndian.INSTANCE.metroHash64(seed, input, access, off, len);
            }
        }
    }

    public static LongHashFunction asLongHashFunctionWithoutSeed() {
        return AsLongHashFunction.INSTANCE;
    }

    public static LongHashFunction asLongHashFunctionWithSeed(long seed) {
        return new AsLongHashFunctionSeeded(seed);
    }

    private static class AsLongHashFunctionSeeded extends AsLongHashFunction {
        private final long seed;
        private final long voidHash;

        public AsLongHashFunctionSeeded(long seed) {
            this.seed = seed;
            voidHash = MetroHash.finalize((seed + k2) * k0);
        }

        @Override
        public long hashVoid() {
            return voidHash;
        }

        @Override
        protected long seed() {
            return seed;
        }
    }
}
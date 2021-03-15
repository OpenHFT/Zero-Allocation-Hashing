package net.openhft.hashing;

import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static net.openhft.hashing.Util.NATIVE_LITTLE_ENDIAN;

class MetroHash {
    //primes
    private static final long k0 = 0xD6D018F5L;
    private static final long k1 = 0xA2AA033BL;
    private static final long k2 = 0x62992FC1L;
    private static final long k3 = 0x30BC5B29L;

    static <T> long metroHash64(long seed, T input, Access<T> access, long off, long length) {
        long remaining = length;

        long h = (seed + k2) * k0;

        if (length >= 32) {
            long v0 = h;
            long v1 = h;
            long v2 = h;
            long v3 = h;

            do {
                v0 += access.i64(input, off) * k0;
                v0 = Long.rotateRight(v0, 29) + v2;
                v1 += access.i64(input, off + 8) * k1;
                v1 = Long.rotateRight(v1, 29) + v3;
                v2 += access.i64(input, off + 16) * k2;
                v2 = Long.rotateRight(v2, 29) + v0;
                v3 += access.i64(input, off + 24) * k3;
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
            long v0 = h + (access.i64(input, off) * k2);
            v0 = Long.rotateRight(v0, 29) * k3;
            long v1 = h + (access.i64(input, off + 8) * k2);
            v1 = Long.rotateRight(v1, 29) * k3;
            v0 ^= Long.rotateRight(v0 * k0, 21) + v1;
            v1 ^= Long.rotateRight(v1 * k3, 21) + v0;
            h += v1;

            off += 16;
            remaining -= 16;
        }

        if (remaining >= 8) {
            h += access.i64(input, off) * k3;
            h ^= Long.rotateRight(h, 55) * k1;

            off += 8;
            remaining -= 8;
        }

        if (remaining >= 4) {
            h += access.u32(input, off) * k3;
            h ^= Long.rotateRight(h, 26) * k1;

            off += 4;
            remaining -= 4;
        }

        if (remaining >= 2) {
            h += access.u16(input, off) * k3;
            h ^= Long.rotateRight(h, 48) * k1;

            off += 2;
            remaining -= 2;
        }

        if (remaining >= 1) {
            h += access.u8(input, off) * k3;
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

    private static class AsLongHashFunction extends LongHashFunction {
        private static final long serialVersionUID = 0L;
        private static final AsLongHashFunction SEEDLESS_INSTANCE = new AsLongHashFunction();
        private static final long VOID_HASH = MetroHash.finalize(k2 * k0);

        private Object readResolve() {
            return SEEDLESS_INSTANCE;
        }

        protected long seed() {
            return 0L;
        }

        @Override
        public long hashLong(long input) {
            input = Primitives.nativeToLittleEndian(input);
            long h = (seed() + k2) * k0;
            h += input * k3;
            h ^= Long.rotateRight(h, 55) * k1;

            return MetroHash.finalize(h);
        }

        @Override
        public long hashInt(int input) {
            input = Primitives.nativeToLittleEndian(input);
            long h = (seed() + k2) * k0;
            h += Primitives.unsignedInt(input) * k3;
            h ^= Long.rotateRight(h, 26) * k1;

            return MetroHash.finalize(h);
        }

        @Override
        public long hashShort(short input) {
            input = Primitives.nativeToLittleEndian(input);
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
            return VOID_HASH;
        }

        @Override
        public <T> long hash(T input, Access<T> access, long off, long len) {
            long seed = seed();
            return MetroHash.metroHash64(seed, input, access.byteOrder(input, LITTLE_ENDIAN), off, len);
        }
    }

    static LongHashFunction asLongHashFunctionWithoutSeed() {
        return AsLongHashFunction.SEEDLESS_INSTANCE;
    }

    static LongHashFunction asLongHashFunctionWithSeed(long seed) {
        return new AsLongHashFunctionSeeded(seed);
    }

    private static class AsLongHashFunctionSeeded extends AsLongHashFunction {
        private static final long serialVersionUID = 0L;

        private final long seed;
        private final transient long voidHash;

        AsLongHashFunctionSeeded(long seed) {
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

package net.openhft.hashing;

import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static net.openhft.hashing.Util.NATIVE_LITTLE_ENDIAN;

/**
 * Adapted version of WyHash implementation from https://github.com/wangyi-fudan/wyhash
 * Original @author <a href="mailto:godspeed_china@yeah.net">Wang Yi</a>
 * Adapted @author <a href="mailto:firestrand@gmail.com">Travis Silvers</a>
 * This implementation provides endian-independant hash values, but it's slower on big-endian
 * platforms.
 * The original C based version is also much faster.
 */
class WyHash {
    // Primes
    public static final long _wyp0 = 0xa0761d6478bd642fL;
    public static final long _wyp1 = 0xe7037ed1a0b428dbL;
    public static final long _wyp2 = 0x8ebc6af09c88c6e3L;
    public static final long _wyp3 = 0x589965cc75374cc3L;
    public static final long _wyp4 = 0x1d8e4e27c47d124fL;

    private static long _wymum(final long lhs, final long rhs) {
        return Maths.unsignedLongMulXorFold(lhs, rhs);
    }

    private static <T> long _wyr3(final Access<T> access, T in, final long index, long k) {
        return ((long) access.u8(in, index) << 16) |
               ((long) access.u8(in, index + (k >>> 1)) << 8) |
               ((long) access.u8(in, index + k - 1));
    }

    private static <T> long u64Rorate32(final Access<T> access, T in, final long index) {
        return (access.u32(in, index) << 32) | access.u32(in, index + 4);
    }

    /**
     *
     * @param seed seed for the hash
     * @param input the type wrapped by the Access, ex. byte[], ByteBuffer, etc.
     * @param access class wrapping optimized access pattern to the input
     * @param off offset to the input
     * @param length length to read from input
     * @param <T> byte[], ByteBuffer, etc.
     * @return hash result
     */
    static <T> long wyHash64(long seed, T input, Access<T> access, long off, long length) {
        if(length <= 0)
            return 0;
        else if(length<4)
            return _wymum(_wymum(_wyr3(access, input,off,length)^seed^_wyp0,
                                 seed^_wyp1)^seed,length^_wyp4);
        else if(length<=8)
            return _wymum(_wymum(access.u32(input, off) ^ seed ^ _wyp0,
                                 access.u32(input, off + length - 4) ^ seed ^ _wyp1)
                          ^ seed, length ^ _wyp4);
        else if(length<=16)
            return _wymum(_wymum(u64Rorate32(access, input,off)^seed^_wyp0,
                                 u64Rorate32(access, input,off+length-8)^seed^_wyp1)
                          ^seed,length^_wyp4);
        else if(length<=24)
            return _wymum(_wymum(u64Rorate32(access, input,off)^seed^_wyp0,
                                 u64Rorate32(access, input,off+8)^seed^_wyp1)^
                          _wymum(u64Rorate32(access, input,off+length-8)
                                 ^seed^_wyp2,seed^_wyp3),length^_wyp4);
        else if(length<=32)
            return _wymum(_wymum(u64Rorate32(access, input,off)^seed^_wyp0,
                                 u64Rorate32(access, input,off+8)^seed^_wyp1)
                          ^_wymum(u64Rorate32(access, input,off+16)^seed^_wyp2,
                                  u64Rorate32(access, input,off+length-8)^seed^_wyp3),length^_wyp4);
        long see1=seed; long i=length, p=off;
        for(;i>256;i-=256,p+=256){
            seed = _wymum(access.i64(input, p) ^ seed ^ _wyp0,
                          access.i64(input, p + 8) ^ seed ^ _wyp1) ^
                   _wymum(access.i64(input, p + 16) ^ seed ^ _wyp2,
                          access.i64(input, p + 24) ^ seed ^ _wyp3);
            see1 = _wymum(access.i64(input, p + 32) ^ see1 ^ _wyp1,
                          access.i64(input, p + 40) ^ see1 ^ _wyp2) ^
                   _wymum(access.i64(input, p + 48) ^ see1 ^ _wyp3,
                          access.i64(input, p + 56) ^ see1 ^ _wyp0);
            seed = _wymum(access.i64(input, p + 64) ^ seed ^ _wyp0,
                          access.i64(input, p + 72) ^ seed ^ _wyp1) ^
                   _wymum(access.i64(input, p + 80) ^ seed ^ _wyp2,
                          access.i64(input, p + 88) ^ seed ^ _wyp3);
            see1 = _wymum(access.i64(input, p + 96) ^ see1 ^ _wyp1,
                          access.i64(input, p + 104) ^ see1 ^ _wyp2) ^
                   _wymum(access.i64(input, p + 112) ^ see1 ^ _wyp3,
                          access.i64(input, p + 120) ^ see1 ^ _wyp0);
            seed = _wymum(access.i64(input, p + 128) ^ seed ^ _wyp0,
                          access.i64(input, p + 136) ^ seed ^ _wyp1) ^
                   _wymum(access.i64(input, p + 144) ^ seed ^ _wyp2,
                          access.i64(input, p + 152) ^ seed ^ _wyp3);
            see1 = _wymum(access.i64(input, p + 160) ^ see1 ^ _wyp1,
                          access.i64(input, p + 168) ^ see1 ^ _wyp2) ^
                   _wymum(access.i64(input, p + 176) ^ see1 ^ _wyp3,
                          access.i64(input, p + 184) ^ see1 ^ _wyp0);
            seed = _wymum(access.i64(input, p + 192) ^ seed ^ _wyp0,
                          access.i64(input, p + 200) ^ seed ^ _wyp1) ^
                   _wymum(access.i64(input, p + 208) ^ seed ^ _wyp2,
                          access.i64(input, p + 216) ^ seed ^ _wyp3);
            see1 = _wymum(access.i64(input, p + 224) ^ see1 ^ _wyp1,
                          access.i64(input, p + 232) ^ see1 ^ _wyp2) ^
                   _wymum(access.i64(input, p + 240) ^ see1 ^ _wyp3,
                          access.i64(input, p + 248) ^ see1 ^ _wyp0);
        }
        for (; i > 32; i -= 32, p += 32) {
            seed = _wymum(access.i64(input, p) ^ seed ^ _wyp0,
                          access.i64(input, p + 8) ^ seed ^ _wyp1);
            see1 = _wymum(access.i64(input, p + 16) ^ see1 ^ _wyp2,
                          access.i64(input, p + 24) ^ see1 ^ _wyp3);
        }
        if (i < 4) {
            seed = _wymum(_wyr3(access, input, p, i) ^ seed ^ _wyp0, seed ^ _wyp1);
        } else if (i <= 8) {
            seed = _wymum(access.u32(input, p) ^ seed ^ _wyp0,
                          access.u32(input, p + i - 4) ^ seed ^ _wyp1);
        } else if (i <= 16) {
            seed = _wymum(u64Rorate32(access, input, p) ^ seed ^ _wyp0,
                          u64Rorate32(access, input, p + i - 8) ^ seed ^ _wyp1);
        } else if (i <= 24) {
            seed = _wymum(u64Rorate32(access, input, p) ^ seed ^ _wyp0,
                          u64Rorate32(access, input, p + 8) ^ seed ^ _wyp1);
            see1 = _wymum(u64Rorate32(access, input, p + i - 8) ^ see1 ^ _wyp2, see1 ^ _wyp3);
        } else {
            seed = _wymum(u64Rorate32(access, input, p) ^ seed ^ _wyp0,
                          u64Rorate32(access, input, p + 8) ^ seed ^ _wyp1);
            see1 = _wymum(u64Rorate32(access, input, p + 16) ^ see1 ^ _wyp2,
                          u64Rorate32(access, input, p + i - 8) ^ see1 ^ _wyp3);
        }
        return _wymum(seed ^ see1, length ^ _wyp4);
    }

    static LongHashFunction asLongHashFunctionWithoutSeed() {
        return AsLongHashFunction.SEEDLESS_INSTANCE;
    }

    private static class AsLongHashFunction extends LongHashFunction {
        private static final long serialVersionUID = 0L;
        static final AsLongHashFunction SEEDLESS_INSTANCE = new AsLongHashFunction();

        private Object readResolve() {
            return SEEDLESS_INSTANCE;
        }

        public long seed() {
            return 0L;
        }

        @Override
        public long hashLong(long input) {
            input = Primitives.nativeToLittleEndian(input);
            long hi = input & 0xFFFFFFFFL;
            long lo = (input >>> 32) & 0xFFFFFFFFL;
            return _wymum(_wymum(hi ^ seed() ^ _wyp0,
                          lo ^ seed() ^ _wyp1)
                   ^ seed(), 8 ^ _wyp4);
        }

        @Override
        public long hashInt(int input) {
            input = Primitives.nativeToLittleEndian(input);
            long longInput = (input & 0xFFFFFFFFL);
            return _wymum(_wymum(longInput ^ seed() ^ _wyp0,
                                 longInput ^ seed() ^ _wyp1)
                          ^ seed(), 4 ^ _wyp4);
        }

        @Override
        public long hashShort(short input) {
            input = Primitives.nativeToLittleEndian(input);
            long hi = (input >>> 8) & 0xFFL;
            long wyr3 = hi | hi << 8 | (input & 0xFFL) << 16;
            return _wymum(_wymum(wyr3 ^ seed() ^ _wyp0,
                                 seed() ^ _wyp1) ^ seed(), 2 ^ _wyp4);
        }

        @Override
        public long hashChar(final char input) {
            return hashShort((short)input);
        }

        @Override
        public long hashByte(final byte input) {
            long hi = input & 0xFFL;
            long wyr3 = hi | hi << 8 | hi << 16;
            return _wymum(_wymum(wyr3 ^ seed() ^ _wyp0,
                                 seed() ^ _wyp1) ^ seed(), 1 ^ _wyp4);
        }

        @Override
        public long hashVoid() {
            return 0;
        }

        @Override
        public <T> long hash(final T input, final Access<T> access,
                             final long off, final long len) {
            long seed = seed();
            return WyHash.wyHash64(seed, input, access.byteOrder(input, LITTLE_ENDIAN), off, len);
        }
    }

    static LongHashFunction asLongHashFunctionWithSeed(long seed) {
        return new AsLongHashFunctionSeeded(seed);
    }

    private static class AsLongHashFunctionSeeded extends AsLongHashFunction {
        private static final long serialVersionUID = 0L;

        private final long seed;

        private AsLongHashFunctionSeeded(long seed) {
            this.seed = seed;
        }

        @Override
        public long seed() {
            return seed;
        }
    }
}

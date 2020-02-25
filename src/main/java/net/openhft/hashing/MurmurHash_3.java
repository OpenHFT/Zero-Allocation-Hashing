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

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import static java.lang.Long.reverseBytes;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static net.openhft.hashing.Util.NATIVE_LITTLE_ENDIAN;
import static net.openhft.hashing.Primitives.unsignedInt;

/**
 * Derived from https://github.com/google/guava/blob/fa95e381e665d8ee9639543b99ed38020c8de5ef
 * /guava/src/com/google/common/hash/Murmur3_128HashFunction.java
 */
@ParametersAreNonnullByDefault
class MurmurHash_3 {
    @NotNull
    private static final MurmurHash_3 INSTANCE = new MurmurHash_3();

    @NotNull
    private static final MurmurHash_3 NATIVE_MURMUR = NATIVE_LITTLE_ENDIAN ?
            MurmurHash_3.INSTANCE : BigEndian.INSTANCE;

    private static final long C1 = 0x87c37b91114253d5L;
    private static final long C2 = 0x4cf5ad432745937fL;

    private MurmurHash_3() {}

    <T> long fetch64(Access<T> access, @Nullable T in, long off) {
        return access.getLong(in, off);
    }

    <T> int fetch32(Access<T> access, @Nullable T in, long off) {
        return access.getInt(in, off);
    }

    long toLittleEndian(long v) {
        return v;
    }

    int toLittleEndian(int v) {
        return v;
    }

    int toLittleEndianShort(int unsignedShort) {
        return unsignedShort;
    }

    public <T> long hash(long seed, @Nullable T input, Access<T> access, long offset, long length, @Nullable long[] result) {
        long h1 = seed;
        long h2 = seed;
        long remaining = length;
        while (remaining >= 16L) {
            long k1 = fetch64(access, input, offset);
            long k2 = fetch64(access, input, offset + 8L);
            offset += 16L;
            remaining -= 16L;
            h1 ^= mixK1(k1);

            h1 = Long.rotateLeft(h1, 27);
            h1 += h2;
            h1 = h1 * 5L + 0x52dce729L;

            h2 ^= mixK2(k2);

            h2 = Long.rotateLeft(h2, 31);
            h2 += h1;
            h2 = h2 * 5L + 0x38495ab5L;
        }

        if (remaining > 0L) {
            long k1 = 0L;
            long k2 = 0L;
            switch ((int) remaining) {
                case 15:
                    k2 ^= ((long) access.getUnsignedByte(input, offset + 14L)) << 48;// fall through
                case 14:
                    k2 ^= ((long) access.getUnsignedByte(input, offset + 13L)) << 40;// fall through
                case 13:
                    k2 ^= ((long) access.getUnsignedByte(input, offset + 12L)) << 32;// fall through
                case 12:
                    k2 ^= ((long) access.getUnsignedByte(input, offset + 11L)) << 24;// fall through
                case 11:
                    k2 ^= ((long) access.getUnsignedByte(input, offset + 10L)) << 16;// fall through
                case 10:
                    k2 ^= ((long) access.getUnsignedByte(input, offset + 9L)) << 8; // fall through
                case 9:
                    k2 ^= ((long) access.getUnsignedByte(input, offset + 8L)); // fall through
                case 8:
                    k1 ^= fetch64(access, input, offset);
                    break;
                case 7:
                    k1 ^= ((long) access.getUnsignedByte(input, offset + 6L)) << 48; // fall through
                case 6:
                    k1 ^= ((long) access.getUnsignedByte(input, offset + 5L)) << 40; // fall through
                case 5:
                    k1 ^= ((long) access.getUnsignedByte(input, offset + 4L)) << 32; // fall through
                case 4:
                    k1 ^= Primitives.unsignedInt(fetch32(access, input, offset));
                    break;
                case 3:
                    k1 ^= ((long) access.getUnsignedByte(input, offset + 2L)) << 16; // fall through
                case 2:
                    k1 ^= ((long) access.getUnsignedByte(input, offset + 1L)) << 8; // fall through
                case 1:
                    k1 ^= ((long) access.getUnsignedByte(input, offset));
                case 0:
                    break;
                default:
                    throw new AssertionError("Should never get here.");
            }
            h1 ^= mixK1(k1);
            h2 ^= mixK2(k2);
        }

        // This version appears to be working slower

//        if (remaining > 0L) {
//            long k1 = 0L;
//            long k2 = 0L;
//            megaSwitch:
//            {
//                fetch0_7:
//                {
//                    fetch8_11:
//                    {
//                        fetch0_3:
//                        {
//                            switch ((int) remaining) {
//                                case 15:
//                                    k2 ^= ((long) access.getUnsignedByte(input, offset + 14L)) << 48;
//                                case 14:
//                                    k2 ^= ((long) toLittleEndianShort(
//                                            access.getUnsignedShort(input, offset + 12L))) << 32;
//                                    break fetch8_11;
//                                case 13:
//                                    k2 ^= ((long) access.getUnsignedByte(input, offset + 12L)) << 32;
//                                case 12:
//                                    break fetch8_11;
//                                case 11:
//                                    k2 ^= ((long) access.getUnsignedByte(input, offset + 10L)) << 16;
//                                case 10:
//                                    k2 ^= (long) toLittleEndianShort(
//                                            access.getUnsignedShort(input, offset + 8L));
//                                    break fetch0_7;
//                                case 9:
//                                    k2 ^= ((long) access.getUnsignedByte(input, offset + 8L));
//                                case 8:
//                                    break fetch0_7;
//                                case 7:
//                                    k1 ^= ((long) access.getUnsignedByte(input, offset + 6L)) << 48;
//                                case 6:
//                                    k1 ^= ((long) toLittleEndianShort(
//                                            access.getUnsignedShort(input, offset + 4L))) << 32;
//                                    break fetch0_3;
//                                case 5:
//                                    k1 ^= ((long) access.getUnsignedByte(input, offset + 4L)) << 32;
//                                case 4:
//                                    break fetch0_3;
//                                case 3:
//                                    k1 ^= ((long) access.getUnsignedByte(input, offset + 2L)) << 16;
//                                case 2:
//                                    k1 ^= (long) toLittleEndianShort(
//                                            access.getUnsignedShort(input, offset));
//                                    break megaSwitch;
//                                case 1:
//                                    k1 ^= ((long) access.getUnsignedByte(input, offset));
//                                    break megaSwitch;
//                                default:
//                                    throw new AssertionError();
//                            }
//                        } // fetch0_3
//                        k1 ^= unsignedInt(fetch32(access, input, offset));
//                        break megaSwitch;
//                    } // fetch8_11
//                    k2 ^= unsignedInt(fetch32(access, input, offset + 8L));
//                } // fetch0_7
//                k1 ^= fetch64(access, input, offset);
//            } // megaSwitch
//
//            h1 ^= mixK1(k1);
//            h2 ^= mixK2(k2);
//        }

        return finalize(length, h1, h2, result);
    }

    private static long finalize(long length, long h1, long h2, @Nullable long[] result) {
        h1 ^= length;
        h2 ^= length;

        h1 += h2;
        h2 += h1;

        h1 = fmix64(h1);
        h2 = fmix64(h2);


        if (null != result) {
            h1 += h2;
            result[0] = h1;
            result[1] = h1 + h2;
            return h1;
        } else {
            return h1 + h2;
        }
    }

    private static long fmix64(long k) {
        k ^= k >>> 33;
        k *= 0xff51afd7ed558ccdL;
        k ^= k >>> 33;
        k *= 0xc4ceb9fe1a85ec53L;
        k ^= k >>> 33;
        return k;
    }

    private static long mixK1(long k1) {
        k1 *= C1;
        k1 = Long.rotateLeft(k1, 31);
        k1 *= C2;
        return k1;
    }

    private static long mixK2(long k2) {
        k2 *= C2;
        k2 = Long.rotateLeft(k2, 33);
        k2 *= C1;
        return k2;
    }

    private static class BigEndian extends MurmurHash_3 {
        @NotNull
        private static final BigEndian INSTANCE = new BigEndian();
        private BigEndian() {}

        @Override
        <T> long fetch64(Access<T> access, @Nullable T in, long off) {
            return reverseBytes(super.fetch64(access, in, off));
        }

        @Override
        <T> int fetch32(Access<T> access, @Nullable T in, long off) {
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

        @Override
        int toLittleEndianShort(int unsignedShort) {
            return ((unsignedShort & 0xFF) << 8) | (unsignedShort >> 8);
        }
    }

    private static class AsLongTupleHashFunction extends DualHashFunction {
        private static final long serialVersionUID = 0L;
        @NotNull
        private static final AsLongTupleHashFunction SEEDLESS_INSTANCE = new AsLongTupleHashFunction();
        @NotNull
        private static final LongHashFunction SEEDLESS_INSTANCE_LONG = SEEDLESS_INSTANCE.asLongHashFunction();

        private Object readResolve() {
            return SEEDLESS_INSTANCE;
        }

        @Override
        public int bitsLength() {
            return 128;
        }
        @Override
        @NotNull
        public long[] newResultArray() {
            return new long[2]; // override for a little performance
        }

        long seed() {
            return 0L;
        }

        protected long hashNativeLong(long nativeLong, long len, @Nullable long[] result) {
            long h1 = mixK1(nativeLong);
            long h2 = 0L;
            return MurmurHash_3.finalize(len, h1, h2, result);
        }

        @Override
        public long dualHashLong(long input, @Nullable long[] result) {
            return hashNativeLong(NATIVE_MURMUR.toLittleEndian(input), 8L, result);
        }

        @Override
        public long dualHashInt(int input, @Nullable long[] result) {
            return hashNativeLong(unsignedInt(NATIVE_MURMUR.toLittleEndian(input)), 4L, result);
        }

        @Override
        public long dualHashShort(short input, @Nullable long[] result) {
            return hashNativeLong(
                    (long) NATIVE_MURMUR.toLittleEndianShort(Primitives.unsignedShort(input)), 2L, result);
        }

        @Override
        public long dualHashChar(char input, @Nullable long[] result) {
            return hashNativeLong((long) NATIVE_MURMUR.toLittleEndianShort((int) input), 2L, result);
        }

        @Override
        public long dualHashByte(byte input, @Nullable long[] result) {
            return hashNativeLong((long) Primitives.unsignedByte((int) input), 1L, result);
        }

        @Override
        public long dualHashVoid(@Nullable long[] result) {
            if (null != result) {
                result[0] = 0;
                result[1] = 0;
            }
            return 0;
        }

        @Override
        public <T> long dualHash(@Nullable T input, Access<T> access, long off, long len, @Nullable long[] result) {
            long seed = seed();
            if (access.byteOrder(input) == LITTLE_ENDIAN) {
                return MurmurHash_3.INSTANCE.hash(seed, input, access, off, len, result);
            } else {
                return BigEndian.INSTANCE.hash(seed, input, access, off, len, result);
            }
        }
    }

    @NotNull
    static LongTupleHashFunction asLongTupleHashFunctionWithoutSeed() {
        return AsLongTupleHashFunction.SEEDLESS_INSTANCE;
    }
    @NotNull
    static LongHashFunction asLongHashFunctionWithoutSeed() {
        return AsLongTupleHashFunction.SEEDLESS_INSTANCE_LONG;
    }

    private static class AsLongTupleHashFunctionSeeded extends AsLongTupleHashFunction {
        private static final long serialVersionUID = 0L;

        private final long seed;
        @NotNull
        private final transient long[] voidHash = newResultArray();

        private AsLongTupleHashFunctionSeeded(long seed) {
            this.seed = seed;
            MurmurHash_3.finalize(0L, seed, seed, voidHash);
        }

        @Override
        long seed() {
            return seed;
        }

        @Override
        protected long hashNativeLong(long nativeLong, long len, @Nullable long[] result) {
            long seed = this.seed;
            long h1 = seed ^ mixK1(nativeLong);
            long h2 = seed;
            return MurmurHash_3.finalize(len, h1, h2, result);
        }

        @Override
        public long dualHashVoid(@Nullable long[] result) {
            if (null != result) {
                result[0] = voidHash[0];
                result[1] = voidHash[1];
            }
            return voidHash[0];
        }
    }

    @NotNull
    static LongTupleHashFunction asLongTupleHashFunctionWithSeed(long seed) {
        return new AsLongTupleHashFunctionSeeded(seed);
    }
    @NotNull
    static LongHashFunction asLongHashFunctionWithSeed(long seed) {
        return new AsLongTupleHashFunctionSeeded(seed).asLongHashFunction();
    }
}

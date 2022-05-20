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

import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.nio.ByteOrder;

import static net.openhft.hashing.Primitives.*;
import static net.openhft.hashing.Util.NATIVE_LITTLE_ENDIAN;

class UnsafeAccess extends Access<Object> {
    static final UnsafeAccess INSTANCE;
    static final UnsafeAccess OLD_INSTANCE = NATIVE_LITTLE_ENDIAN
                                             ? new OldUnsafeAccessLittleEndian()
                                             : new OldUnsafeAccessBigEndian();

    static final Unsafe UNSAFE;
    static final long BOOLEAN_BASE;
    static final long BYTE_BASE;
    static final long CHAR_BASE;
    static final long SHORT_BASE;
    static final long INT_BASE;
    static final long LONG_BASE;

    static final byte TRUE_BYTE_VALUE;
    static final byte FALSE_BYTE_VALUE;

    static {
        try {
            Field theUnsafe = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            UNSAFE = (Unsafe) theUnsafe.get(null);
            BOOLEAN_BASE = UNSAFE.arrayBaseOffset(boolean[].class);
            BYTE_BASE = UNSAFE.arrayBaseOffset(byte[].class);
            CHAR_BASE = UNSAFE.arrayBaseOffset(char[].class);
            SHORT_BASE = UNSAFE.arrayBaseOffset(short[].class);
            INT_BASE = UNSAFE.arrayBaseOffset(int[].class);
            LONG_BASE = UNSAFE.arrayBaseOffset(long[].class);
        } catch (Exception e) {
            throw new AssertionError(e);
        }

        UnsafeAccess inst = new UnsafeAccess();
        try {
            inst.getByte(new byte[1], BYTE_BASE);
        } catch (final Throwable e) {
            // Unsafe in pre-Nougat Android does not have getByte(), fall back to workround
            inst = OLD_INSTANCE;
        } finally {
            INSTANCE = inst;
        }

        TRUE_BYTE_VALUE = (byte)INSTANCE.getByte(new boolean[] {true}, BOOLEAN_BASE);
        FALSE_BYTE_VALUE = (byte)INSTANCE.getByte(new boolean[] {false}, BOOLEAN_BASE);
    }

    private UnsafeAccess() {}

    @Override
    public long getLong(Object input, long offset) {
        return UNSAFE.getLong(input, offset);
    }

    @Override
    public long getUnsignedInt(Object input, long offset) {
        return unsignedInt(getInt(input, offset));
    }

    @Override
    public int getInt(Object input, long offset) {
        return UNSAFE.getInt(input, offset);
    }

    @Override
    public int getUnsignedShort(Object input, long offset) {
        return unsignedShort(getShort(input, offset));
    }

    @Override
    public int getShort(Object input, long offset) {
        return UNSAFE.getShort(input, offset);
    }

    @Override
    public int getUnsignedByte(Object input, long offset) {
        return unsignedByte(getByte(input, offset));
    }

    @Override
    public int getByte(Object input, long offset) {
        return UNSAFE.getByte(input, offset);
    }

    @Override
    public ByteOrder byteOrder(Object input) {
        return ByteOrder.nativeOrder();
    }

    private static class OldUnsafeAccessLittleEndian extends UnsafeAccess {
        @Override
        public int getShort(final Object input, final long offset) {
            return UNSAFE.getInt(input, offset - 2) >> 16;
        }

        @Override
        public int getByte(final Object input, final long offset) {
            return UNSAFE.getInt(input, offset - 3) >> 24;
        }
    }

    private static class OldUnsafeAccessBigEndian extends UnsafeAccess {
        @Override
        public int getShort(final Object input, final long offset) {
            return (int)(short)UNSAFE.getInt(input, offset - 2);
        }

        @Override
        public int getByte(final Object input, final long offset) {
            return (int)(byte)UNSAFE.getInt(input, offset - 3);
        }
    }
}

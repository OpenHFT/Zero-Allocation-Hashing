/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.lang.reflect.Field;
import javax.annotation.ParametersAreNonnullByDefault;

@ParametersAreNonnullByDefault
enum HotSpotPrior7u6StringHash implements StringHash {
    INSTANCE;

    private static final long valueOffset;
    private static final long offsetOffset;

    static {
        try {
            Field valueField = String.class.getDeclaredField("value");
            valueOffset = UnsafeAccess.UNSAFE.objectFieldOffset(valueField);

            Field offsetField = String.class.getDeclaredField("offset");
            offsetOffset = UnsafeAccess.UNSAFE.objectFieldOffset(offsetField);
        } catch (NoSuchFieldException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public long longHash(String s, LongHashFunction hashFunction, int off, int len) {
        char[] value = (char[]) UnsafeAccess.UNSAFE.getObject(s, valueOffset);
        int offset = UnsafeAccess.UNSAFE.getInt(s, offsetOffset);
        return hashFunction.hashChars(value, offset + off, len);
    }

    @Override
    public void hash(final String s, final LongTupleHashFunction hashFunction,
                    final int off, final int len, final long[] result) {
        final char[] value = (char[]) UnsafeAccess.UNSAFE.getObject(s, valueOffset);
        final int offset = UnsafeAccess.UNSAFE.getInt(s, offsetOffset);
        hashFunction.hashChars(value, offset + off, len, result);
    }
}

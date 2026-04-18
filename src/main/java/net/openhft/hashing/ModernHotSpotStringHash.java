/*
 * Copyright 2013-2026 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.lang.reflect.Field;
import javax.annotation.ParametersAreNonnullByDefault;

@ParametersAreNonnullByDefault
enum ModernHotSpotStringHash implements StringHash {
    INSTANCE;

    private static final long valueOffset;

    static {
        try {
            Field valueField = String.class.getDeclaredField("value");
            valueOffset = UnsafeAccess.UNSAFE.objectFieldOffset(valueField);
        } catch (NoSuchFieldException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public long longHash(String s, LongHashFunction hashFunction, int off, int len) {
        char[] value = (char[]) UnsafeAccess.UNSAFE.getObject(s, valueOffset);
        return hashFunction.hashChars(value, off, len);
    }

    @Override
    public void hash(final String s, final LongTupleHashFunction hashFunction,
                    final int off, final int len, final long[] result) {
        final char[] value = (char[]) UnsafeAccess.UNSAFE.getObject(s, valueOffset);
        hashFunction.hashChars(value, off, len, result);
    }
}

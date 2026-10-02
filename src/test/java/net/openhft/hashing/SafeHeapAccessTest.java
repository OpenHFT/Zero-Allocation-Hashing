/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.util.Random;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertArrayEquals;

public class SafeHeapAccessTest {
    private static final LongHashFunction[] FUNCTIONS = {
        LongHashFunction.xx(), LongHashFunction.xx3(), LongHashFunction.city_1_1(),
        LongHashFunction.murmur_3(), LongHashFunction.wy_3(), LongHashFunction.metro()
    };

    @Test
    public void safeBackendMatchesPublicApiForAllArrayTypes() {
        final Random random = new Random(42);
        for (final LongHashFunction f : FUNCTIONS) {
            for (int len = 0; len < 100; len++) {
                final byte[] bytes = new byte[len * 8];
                random.nextBytes(bytes);
                final java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.nativeOrder());
                final long[] longs = new long[len];
                final int[] ints = new int[len * 2];
                final short[] shorts = new short[len * 4];
                final char[] chars = new char[len * 4];
                bb.asLongBuffer().get(longs);
                bb.asIntBuffer().get(ints);
                bb.asShortBuffer().get(shorts);
                for (int i = 0; i < chars.length; i++) {
                    chars[i] = (char) shorts[i];
                }
                final Access<Object> a = SafeHeapAccess.INSTANCE;
                assertEquals(f.hashBytes(bytes), f.hash(bytes, a, 0, bytes.length));
                assertEquals(f.hashLongs(longs), f.hash(longs, a, 0, longs.length * 8L));
                assertEquals(f.hashInts(ints), f.hash(ints, a, 0, ints.length * 4L));
                assertEquals(f.hashShorts(shorts), f.hash(shorts, a, 0, shorts.length * 2L));
                assertEquals(f.hashChars(chars), f.hash(chars, a, 0, chars.length * 2L));
            }
        }
    }

    @Test
    public void tupleHashMatches() {
        final byte[] bytes = new byte[77];
        new Random(1).nextBytes(bytes);
        final LongTupleHashFunction f = LongTupleHashFunction.xx128();
        assertArrayEquals(f.hashBytes(bytes), f.hash(bytes, SafeHeapAccess.INSTANCE, 0, bytes.length));
    }
}

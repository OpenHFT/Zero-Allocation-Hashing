/*
 * Copyright 2013-2026 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class DualHashFunctionTest {

    @Test(expected = IllegalArgumentException.class)
    public void hashLongRejectsTooSmallResultArray() {
        LongTupleHashFunction tuple = XXH3.asLongTupleHashFunctionWithoutSeed();
        tuple.hashLong(17L, new long[0]);
    }

    @Test
    public void longHashViewMatchesTupleFirstWord() {
        LongTupleHashFunction tuple = XXH3.asLongTupleHashFunctionWithoutSeed();
        long value = 123456789L;
        long[] viaAllocation = tuple.hashLong(value);

        long[] reuse = new long[viaAllocation.length];
        tuple.hashLong(value, reuse);

        assertArrayEquals(viaAllocation, reuse);
        long asLong = ((DualHashFunction) tuple).asLongHashFunction().hashLong(value);
        assertEquals(viaAllocation[0], asLong);
    }
}

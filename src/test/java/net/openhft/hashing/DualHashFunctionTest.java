/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DualHashFunctionTest {

    @Test
    void hashLongRejectsTooSmallResultArray() {
        assertThrows(IllegalArgumentException.class, () -> {
            LongTupleHashFunction tuple = XXH3.asLongTupleHashFunctionWithoutSeed();
            tuple.hashLong(17L, new long[0]);
        });
    }

    @Test
    void longHashViewMatchesTupleFirstWord() {
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

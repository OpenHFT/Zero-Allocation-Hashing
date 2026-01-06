/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class DualHashFunctionTest {

    @Test
    public void hashLongRejectsTooSmallResultArray() {
        LongTupleHashFunction tuple = XXH3.asLongTupleHashFunctionWithoutSeed();
        assertThrows(IllegalArgumentException.class, () -> tuple.hashLong(17L, new long[0]), "hashLong rejects too small result array");
    }

    @Test
    public void longHashViewMatchesTupleFirstWord() {
        LongTupleHashFunction tuple = XXH3.asLongTupleHashFunctionWithoutSeed();
        long value = 123456789L;
        long[] viaAllocation = tuple.hashLong(value);

        long[] reuse = new long[viaAllocation.length];
        tuple.hashLong(value, reuse);

        assertArrayEquals(viaAllocation, reuse, "tuple hashLong reuse matches allocation form");
        long asLong = ((DualHashFunction) tuple).asLongHashFunction().hashLong(value);
        assertEquals(viaAllocation[0], asLong, "asLongHashFunction matches tuple low word");
    }
}

/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Random;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MurmurHash3Test {

    @Test
    public void testMurmurWithoutSeed() {
        LongHashFunction f = LongHashFunction.murmur_3();
        byte[] data = {0, 1, 2, 3, 4, 5, 6, 7};
        long expected = ByteBuffer.wrap(Hashing.murmur3_128().hashBytes(data).asBytes())
                .order(ByteOrder.LITTLE_ENDIAN)
                .getLong(0);
        assertEquals(expected, f.hashBytes(data), "murmur_3 low64 matches reference (no seed)");
        testMurmur(LongTupleHashFunction.murmur_3(), LongHashFunction.murmur_3(), Hashing.murmur3_128());
    }

    @Test
    public void testMurmurWithSeed() {
        LongHashFunction f = LongHashFunction.murmur_3(42L);
        byte[] data = {0, 1, 2, 3, 4, 5, 6, 7};
        long expected = ByteBuffer.wrap(Hashing.murmur3_128(42).hashBytes(data).asBytes())
                .order(ByteOrder.LITTLE_ENDIAN)
                .getLong(0);
        assertEquals(expected, f.hashBytes(data), "murmur_3 low64 matches reference (seed=42)");
        testMurmur(LongTupleHashFunction.murmur_3(42L), LongHashFunction.murmur_3(42L), Hashing.murmur3_128(42));
    }

    private void testMurmur(LongTupleHashFunction tested, LongHashFunction tested2, HashFunction referenceFromGuava) {
        byte[] testData = new byte[1024];
        for (int i = 0; i < testData.length; i++) {
            testData[i] = (byte) i;
        }
        for (int i = 0; i < testData.length; i++) {
            byte[] data = Arrays.copyOf(testData, i);
            byte[] ehBytes = referenceFromGuava.hashBytes(data).asBytes();
            long[] eh = new long[(ehBytes.length + 7) / 8];
            ByteBuffer.wrap(ehBytes).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().get(eh);

            LongTupleHashFunctionChecks.test(tested, data, eh);

            LongHashFunctionChecks.test(tested2, data, eh[0]); // test as LongHashFunction
        }
    }
}

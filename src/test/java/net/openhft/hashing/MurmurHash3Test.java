/*
 * Copyright 2013-2026 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import org.junit.Test;

import java.util.Arrays;
import java.util.Random;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MurmurHash3Test {

    @Test
    public void testMurmurWithoutSeed() {
        testMurmur(LongTupleHashFunction.murmur_3(), LongHashFunction.murmur_3(), Hashing.murmur3_128());
    }

    @Test
    public void testMurmurWithSeed() {
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

            LongTupleHashFunctionTest.test(tested, data, eh);

            LongHashFunctionTest.test(tested2, data, eh[0]); // test as LongHashFunction
        }
    }
}

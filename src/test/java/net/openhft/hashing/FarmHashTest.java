//
// Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
//

package net.openhft.hashing;

import org.junit.Test;

/**
 * This tests coherence of supporting functions like hashInt(), hashLong(), hashChars etc.
 * Algorithm is tested in OriginalFarmHashTest
 */
public class FarmHashTest {

    @Test
    public void testUo() {
        for (int len = 0; len < 1026; len++) {
            byte[] data = new byte[len];
            for (int i = 0; i < len; i++) {
                data[i] = (byte) i;
            }
            LongHashFunction f = LongHashFunction.farmUo();
            LongHashFunctionTest.test(f, data, f.hashBytes(data));

            f = LongHashFunction.farmUo(42);
            LongHashFunctionTest.test(f, data, f.hashBytes(data));

            f = LongHashFunction.farmUo(42, 123);
            LongHashFunctionTest.test(f, data, f.hashBytes(data));
        }
    }

    @Test
    public void testNa() {
        for (int len = 0; len < 1026; len++) {
            byte[] data = new byte[len];
            for (int i = 0; i < len; i++) {
                data[i] = (byte) i;
            }
            LongHashFunction f = LongHashFunction.farmNa();
            LongHashFunctionTest.test(f, data, f.hashBytes(data));

            f = LongHashFunction.farmNa(42);
            LongHashFunctionTest.test(f, data, f.hashBytes(data));

            f = LongHashFunction.farmNa(42, 123);
            LongHashFunctionTest.test(f, data, f.hashBytes(data));
        }
    }
}

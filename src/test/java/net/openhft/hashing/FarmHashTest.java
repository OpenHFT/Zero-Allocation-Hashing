/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
            long expected = f.hashBytes(data);
            if (len == 0) {
                assertEquals(expected, f.hashVoid(), "farmUo hashVoid matches hashBytes(empty)");
            }
            LongHashFunctionChecks.test(f, data, expected);

            f = LongHashFunction.farmUo(42);
            expected = f.hashBytes(data);
            if (len == 0) {
                assertEquals(expected, f.hashVoid(), "farmUo seed=42 hashVoid matches hashBytes(empty)");
            }
            LongHashFunctionChecks.test(f, data, expected);

            f = LongHashFunction.farmUo(42, 123);
            expected = f.hashBytes(data);
            if (len == 0) {
                assertEquals(expected, f.hashVoid(), "farmUo seeds=42,123 hashVoid matches hashBytes(empty)");
            }
            LongHashFunctionChecks.test(f, data, expected);
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
            long expected = f.hashBytes(data);
            if (len == 0) {
                assertEquals(expected, f.hashVoid(), "farmNa hashVoid matches hashBytes(empty)");
            }
            LongHashFunctionChecks.test(f, data, expected);

            f = LongHashFunction.farmNa(42);
            expected = f.hashBytes(data);
            if (len == 0) {
                assertEquals(expected, f.hashVoid(), "farmNa seed=42 hashVoid matches hashBytes(empty)");
            }
            LongHashFunctionChecks.test(f, data, expected);

            f = LongHashFunction.farmNa(42, 123);
            expected = f.hashBytes(data);
            if (len == 0) {
                assertEquals(expected, f.hashVoid(), "farmNa seeds=42,123 hashVoid matches hashBytes(empty)");
            }
            LongHashFunctionChecks.test(f, data, expected);
        }
    }
}

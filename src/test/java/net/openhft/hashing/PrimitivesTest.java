/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class PrimitivesTest {

    private static final long l = 0x0123456789ABCDEFL;
    private static final int i = 0x01234567;
    private static final short s = 0x0123;
    private static final short c = 0x4567;

    private static final long rl = 0xEFCDAB8967452301L;
    private static final int ri = 0x67452301;
    private static final short rs = 0x2301;
    private static final short rc = 0x6745;

    @Test
    public void testLE() {
        assumeTrue(nativeOrder() == LITTLE_ENDIAN);

        assertEquals(l, Primitives.nativeToLittleEndian(l), "LE nativeToLittleEndian(long)");
        assertEquals(i, Primitives.nativeToLittleEndian(i), "LE nativeToLittleEndian(int)");
        assertEquals(s, Primitives.nativeToLittleEndian(s), "LE nativeToLittleEndian(short)");
        assertEquals(c, Primitives.nativeToLittleEndian(c), "LE nativeToLittleEndian(char)");

        assertEquals(rl, Primitives.nativeToBigEndian(l), "LE nativeToBigEndian(long)");
        assertEquals(ri, Primitives.nativeToBigEndian(i), "LE nativeToBigEndian(int)");
        assertEquals(rs, Primitives.nativeToBigEndian(s), "LE nativeToBigEndian(short)");
        assertEquals(rc, Primitives.nativeToBigEndian(c), "LE nativeToBigEndian(char)");
    }

    @Test
    public void testBE() {
        assumeTrue(nativeOrder() == BIG_ENDIAN);

        assertEquals(rl, Primitives.nativeToLittleEndian(l), "BE nativeToLittleEndian(long)");
        assertEquals(ri, Primitives.nativeToLittleEndian(i), "BE nativeToLittleEndian(int)");
        assertEquals(rs, Primitives.nativeToLittleEndian(s), "BE nativeToLittleEndian(short)");
        assertEquals(rc, Primitives.nativeToLittleEndian(c), "BE nativeToLittleEndian(char)");

        assertEquals(l, Primitives.nativeToBigEndian(l), "BE nativeToBigEndian(long)");
        assertEquals(i, Primitives.nativeToBigEndian(i), "BE nativeToBigEndian(int)");
        assertEquals(s, Primitives.nativeToBigEndian(s), "BE nativeToBigEndian(short)");
        assertEquals(c, Primitives.nativeToBigEndian(c), "BE nativeToBigEndian(char)");
    }
}

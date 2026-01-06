/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MathsTest {
    @Test
    public void testUnsignedLongMulXorFold() {
        {
            long x = 0x100000001L;
            long y = 0x200000002L;
            assertEquals(2L ^ 0x400000002L, Maths.unsignedLongMulXorFold(x, y), "unsignedLongMulXorFold (x=0x100000001,y=0x200000002)");
            assertEquals(2L, Maths.unsignedLongMulHigh(x, y), "unsignedLongMulHigh (x=0x100000001,y=0x200000002)");
        }
        {
            long x = -1;
            long y = -1;
            assertEquals((-2) ^ 1, Maths.unsignedLongMulXorFold(x, y), "unsignedLongMulXorFold (x=-1,y=-1)");
            assertEquals(-2L, Maths.unsignedLongMulHigh(x, y), "unsignedLongMulHigh (x=-1,y=-1)");
        }
        {
            long x = -1;
            long y = 0x300000003L;
            assertEquals(0x300000002L ^ (-0x300000003L), Maths.unsignedLongMulXorFold(x, y), "unsignedLongMulXorFold (x=-1,y=0x300000003)");
            assertEquals(0x300000002L, Maths.unsignedLongMulHigh(x, y), "unsignedLongMulHigh (x=-1,y=0x300000003)");
        }
    }
}

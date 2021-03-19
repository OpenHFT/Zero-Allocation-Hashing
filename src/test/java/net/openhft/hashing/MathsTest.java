package net.openhft.hashing;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MathsTest {
    @Test
    public void testUnsignedLongMulXorFold() {
        {
            long x = 0x100000001L;
            long y = 0x200000002L;
            assertEquals(2L ^ 0x400000002L, Maths.unsignedLongMulXorFold(x, y));
            assertEquals(2L, Maths.unsignedLongMulHigh(x, y));
        }
        {
            long x = -1;
            long y = -1;
            assertEquals((-2) ^ 1, Maths.unsignedLongMulXorFold(x, y));
            assertEquals(-2L, Maths.unsignedLongMulHigh(x, y));
        }
        {
            long x = -1;
            long y = 0x300000003L;
            assertEquals(0x300000002L ^ (-0x300000003L), Maths.unsignedLongMulXorFold(x, y));
            assertEquals(0x300000002L, Maths.unsignedLongMulHigh(x, y));
        }
    }
}

package net.openhft.hashing;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MathsTest {
    private static Maths m = Maths.INSTANCE;

    @Test
    public void testUnsignedLongMulXorFold() {
        {
            long x = 0x100000001L;
            long y = 0x200000002L;
            assertEquals(2L ^ 0x400000002L, m.unsignedLongMulXorFold(x, y));
        }
        {
            long x = -1;
            long y = -1;
            assertEquals((-2) ^ 1, m.unsignedLongMulXorFold(x, y));
        }
        {
            long x = -1;
            long y = 0x300000003L;
            assertEquals(0x300000002L ^ (-0x300000003L), m.unsignedLongMulXorFold(x, y));
        }
    }
}

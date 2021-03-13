package net.openhft.hashing;

import org.junit.Test;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

public class PrimitivesTest {

    static final long l = 0x0123456789ABCDEFL;
    static final int i = 0x01234567;
    static final short s = 0x0123;
    static final short c = 0x4567;

    static final long rl = 0xEFCDAB8967452301L;
    static final int ri = 0x67452301;
    static final short rs = 0x2301;
    static final short rc = 0x6745;

    @Test
    public void testLE() {
        assumeTrue(nativeOrder() == LITTLE_ENDIAN);

        assertEquals(l, Primitives.nativeToLittleEndian(l));
        assertEquals(i, Primitives.nativeToLittleEndian(i));
        assertEquals(s, Primitives.nativeToLittleEndian(s));
        assertEquals(c, Primitives.nativeToLittleEndian(c));

        assertEquals(rl, Primitives.nativeToBigEndian(l));
        assertEquals(ri, Primitives.nativeToBigEndian(i));
        assertEquals(rs, Primitives.nativeToBigEndian(s));
        assertEquals(rc, Primitives.nativeToBigEndian(c));
    }

    @Test
    public void testBE() {
        assumeTrue(nativeOrder() == BIG_ENDIAN);

        assertEquals(rl, Primitives.nativeToLittleEndian(l));
        assertEquals(ri, Primitives.nativeToLittleEndian(i));
        assertEquals(rs, Primitives.nativeToLittleEndian(s));
        assertEquals(rc, Primitives.nativeToLittleEndian(c));

        assertEquals(l, Primitives.nativeToBigEndian(l));
        assertEquals(i, Primitives.nativeToBigEndian(i));
        assertEquals(s, Primitives.nativeToBigEndian(s));
        assertEquals(c, Primitives.nativeToBigEndian(c));
    }
}

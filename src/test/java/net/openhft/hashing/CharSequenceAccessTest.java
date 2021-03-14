package net.openhft.hashing;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assume.assumeTrue;
import static java.nio.ByteOrder.*;
import static net.openhft.hashing.Primitives.*;

public class CharSequenceAccessTest {
    static String TEST_STRING = new String(new char[] {0xF0E1,0xD2C3,0xB4A5,0x9687,0xC8E9});

    @Test
    public void testInstanceLE() {
        assumeTrue(nativeOrder() == LITTLE_ENDIAN);

        final Access<CharSequence> nativeAccess = CharSequenceAccess.nativeCharSequenceAccess();

        assertSame(nativeAccess, CharSequenceAccess.charSequenceAccess(LITTLE_ENDIAN));
        assertNotSame(nativeAccess, CharSequenceAccess.charSequenceAccess(BIG_ENDIAN));
    }

    @Test
    public void testInstanceBE() {
        assumeTrue(nativeOrder() == BIG_ENDIAN);

        final Access<CharSequence> nativeAccess = CharSequenceAccess.nativeCharSequenceAccess();

        assertSame(nativeAccess, CharSequenceAccess.charSequenceAccess(BIG_ENDIAN));
        assertNotSame(nativeAccess, CharSequenceAccess.charSequenceAccess(LITTLE_ENDIAN));
    }

    @Test
    public void testInstanceReverse() {
        Access<CharSequence> access = CharSequenceAccess.charSequenceAccess(BIG_ENDIAN);
        assertSame(access, access.reverseAccess().reverseAccess());
        assertNotSame(access.byteOrder(null), access.reverseAccess().byteOrder(null));
        assertSame(access.byteOrder(null, BIG_ENDIAN), access);
        assertNotSame(access.byteOrder(null, LITTLE_ENDIAN), access);

        access = CharSequenceAccess.charSequenceAccess(LITTLE_ENDIAN);
        assertSame(access, access.reverseAccess().reverseAccess());
        assertNotSame(access.byteOrder(null), access.reverseAccess().byteOrder(null));
        assertSame(access.byteOrder(null, LITTLE_ENDIAN), access);
        assertNotSame(access.byteOrder(null, BIG_ENDIAN), access);
    }

    @Test
    public void testLittleEndian() {
        // This case works on both little- and big- endians.

        final Access<CharSequence> access = CharSequenceAccess.charSequenceAccess(LITTLE_ENDIAN);
        final Access<CharSequence> accessR = access.reverseAccess();

        assertEquals(  0x9687B4A5D2C3F0E1L, access.getLong(TEST_STRING, 0));
        assertEquals(0xE99687B4A5D2C3F0L  , access.getLong(TEST_STRING, 1));
        assertEquals(0xE1F0C3D2A5B48796L  , accessR.getLong(TEST_STRING, 0));
        assertEquals(  0xF0C3D2A5B48796E9L, accessR.getLong(TEST_STRING, 1));

        assertEquals(unsignedInt(  0xD2C3F0E1), access.getUnsignedInt(TEST_STRING, 0));
        assertEquals(unsignedInt(0xA5D2C3F0  ), access.getUnsignedInt(TEST_STRING, 1));
        assertEquals(  0xD2C3F0E1, access.getInt(TEST_STRING, 0));
        assertEquals(0xA5D2C3F0  , access.getInt(TEST_STRING, 1));
        assertEquals(unsignedInt(0xE1F0C3D2)  , accessR.getUnsignedInt(TEST_STRING, 0));
        assertEquals(unsignedInt(  0xF0C3D2A5), accessR.getUnsignedInt(TEST_STRING, 1));
        assertEquals(0xE1F0C3D2  , accessR.getInt(TEST_STRING, 0));
        assertEquals(  0xF0C3D2A5, accessR.getInt(TEST_STRING, 1));

        assertEquals(unsignedShort(  0xF0E1), access.getUnsignedShort(TEST_STRING, 0));
        assertEquals(unsignedShort(0xC3F0  ), access.getUnsignedShort(TEST_STRING, 1));
        assertEquals((int)(short)  0xF0E1, access.getShort(TEST_STRING, 0));
        assertEquals((int)(short)0xC3F0  , access.getShort(TEST_STRING, 1));
        assertEquals(unsignedShort(0xE1F0  ), accessR.getUnsignedShort(TEST_STRING, 0));
        assertEquals(unsignedShort(  0xF0C3), accessR.getUnsignedShort(TEST_STRING, 1));
        assertEquals((int)(short)0xE1F0  , accessR.getShort(TEST_STRING, 0));
        assertEquals((int)(short)  0xF0C3, accessR.getShort(TEST_STRING, 1));

        assertEquals(unsignedByte(0xE1), access.getUnsignedByte(TEST_STRING, 0));
        assertEquals(unsignedByte(0xF0), access.getUnsignedByte(TEST_STRING, 1));
        assertEquals((int)(byte)0xE1, access.getByte(TEST_STRING, 0));
        assertEquals((int)(byte)0xF0, access.getByte(TEST_STRING, 1));
        assertEquals(unsignedByte(0xE1), accessR.getUnsignedByte(TEST_STRING, 0));
        assertEquals(unsignedByte(0xF0), accessR.getUnsignedByte(TEST_STRING, 1));
        assertEquals((int)(byte)0xE1, accessR.getByte(TEST_STRING, 0));
        assertEquals((int)(byte)0xF0, accessR.getByte(TEST_STRING, 1));
    }

    @Test
    public void testBigEndian() {
        // This case works on both little- and big- endians.

        final Access<CharSequence> access = CharSequenceAccess.charSequenceAccess(BIG_ENDIAN);

        assertEquals(0xF0E1D2C3B4A59687L  , access.getLong(TEST_STRING, 0));
        assertEquals(  0xE1D2C3B4A59687C8L, access.getLong(TEST_STRING, 1));

        assertEquals(unsignedInt(0xF0E1D2C3), access.getUnsignedInt(TEST_STRING, 0));
        assertEquals(unsignedInt(  0xE1D2C3B4), access.getUnsignedInt(TEST_STRING, 1));
        assertEquals(0xF0E1D2C3, access.getInt(TEST_STRING, 0));
        assertEquals(  0xE1D2C3B4, access.getInt(TEST_STRING, 1));

        assertEquals(unsignedShort(0xF0E1), access.getUnsignedShort(TEST_STRING, 0));
        assertEquals(unsignedShort(  0xE1D2), access.getUnsignedShort(TEST_STRING, 1));
        assertEquals((int)(short)0xF0E1, access.getShort(TEST_STRING, 0));
        assertEquals((int)(short)  0xE1D2, access.getShort(TEST_STRING, 1));

        assertEquals(unsignedByte(0xF0), access.getUnsignedByte(TEST_STRING, 0));
        assertEquals(unsignedByte(0xE1), access.getUnsignedByte(TEST_STRING, 1));
        assertEquals((int)(byte)0xF0, access.getByte(TEST_STRING, 0));
        assertEquals((int)(byte)0xE1, access.getByte(TEST_STRING, 1));
    }
}

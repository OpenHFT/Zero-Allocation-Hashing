package net.openhft.hashing;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static java.nio.ByteOrder.*;
import static net.openhft.hashing.Primitives.*;

public class CharSequenceAccessTest {
    static String TEST_STRING2 = new String(new char[] {0xF0E1,0xD2C3,0xB4A5,0x9687,0xC8E9});

    @Test
    public void testLittleEndian() {
        if (LITTLE_ENDIAN != nativeOrder()) {
            return; // ut is designed for LE machines
        }

        final Access<CharSequence> access = CharSequenceAccess.charSequenceAccess(LITTLE_ENDIAN);
        assertSame(CharSequenceAccess.nativeCharSequenceAccess(), access);

        assertEquals(  0x9687B4A5D2C3F0E1L, access.getLong(TEST_STRING2, 0));
        assertEquals(0xE99687B4A5D2C3F0L  , access.getLong(TEST_STRING2, 1));

        assertEquals(unsignedInt(  0xD2C3F0E1), access.getUnsignedInt(TEST_STRING2, 0));
        assertEquals(unsignedInt(0xA5D2C3F0  ), access.getUnsignedInt(TEST_STRING2, 1));
        assertEquals(  0xD2C3F0E1, access.getInt(TEST_STRING2, 0));
        assertEquals(0xA5D2C3F0  , access.getInt(TEST_STRING2, 1));

        assertEquals(unsignedShort(  0xF0E1), access.getUnsignedShort(TEST_STRING2, 0));
        assertEquals(unsignedShort(0xC3F0  ), access.getUnsignedShort(TEST_STRING2, 1));
        assertEquals((int)(short)  0xF0E1, access.getShort(TEST_STRING2, 0));
        assertEquals((int)(short)0xC3F0  , access.getShort(TEST_STRING2, 1));

        assertEquals(unsignedByte(0xE1), access.getUnsignedByte(TEST_STRING2, 0));
        assertEquals(unsignedByte(0xF0), access.getUnsignedByte(TEST_STRING2, 1));
        assertEquals((int)(byte)0xE1, access.getByte(TEST_STRING2, 0));
        assertEquals((int)(byte)0xF0, access.getByte(TEST_STRING2, 1));
    }

    @Test
    public void testBigEndianOnLEMachine() {
        if (LITTLE_ENDIAN != nativeOrder()) {
            return; // ut is designed for LE machines
        }

        final Access<CharSequence> access = CharSequenceAccess.charSequenceAccess(BIG_ENDIAN);
        assertNotSame(CharSequenceAccess.nativeCharSequenceAccess(), access);

        assertEquals(0xF0E1D2C3B4A59687L  , access.getLong(TEST_STRING2, 0));
        assertEquals(  0xE1D2C3B4A59687C8L, access.getLong(TEST_STRING2, 1));

        assertEquals(unsignedInt(0xF0E1D2C3), access.getUnsignedInt(TEST_STRING2, 0));
        assertEquals(unsignedInt(  0xE1D2C3B4), access.getUnsignedInt(TEST_STRING2, 1));
        assertEquals(0xF0E1D2C3, access.getInt(TEST_STRING2, 0));
        assertEquals(  0xE1D2C3B4, access.getInt(TEST_STRING2, 1));

        assertEquals(unsignedShort(0xF0E1), access.getUnsignedShort(TEST_STRING2, 0));
        assertEquals(unsignedShort(  0xE1D2), access.getUnsignedShort(TEST_STRING2, 1));
        assertEquals((int)(short)0xF0E1, access.getShort(TEST_STRING2, 0));
        assertEquals((int)(short)  0xE1D2, access.getShort(TEST_STRING2, 1));

        assertEquals(unsignedByte(0xF0), access.getUnsignedByte(TEST_STRING2, 0));
        assertEquals(unsignedByte(0xE1), access.getUnsignedByte(TEST_STRING2, 1));
        assertEquals((int)(byte)0xF0, access.getByte(TEST_STRING2, 0));
        assertEquals((int)(byte)0xE1, access.getByte(TEST_STRING2, 1));
    }
}

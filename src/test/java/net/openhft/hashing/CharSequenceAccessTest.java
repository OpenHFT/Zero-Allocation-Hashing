package net.openhft.hashing;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static java.nio.ByteOrder.*;
import static net.openhft.hashing.Primitives.*;

public class CharSequenceAccessTest {
    static String TEST_STRING = "ABCDEFGH";

    static long buildNumber(char ll, char lh, char hl, char hh) {
        return ll | (((int)lh) << 16) | (((long)hl) << 32) | (((long)hh) << 48);
    }

    @Test
    public void testLittleEndian() {
        assertEquals(LITTLE_ENDIAN, nativeOrder()); // ut is designed for LE machines

        final Access<CharSequence> access = CharSequenceAccess.charSequenceAccess(LITTLE_ENDIAN);
	assertSame(CharSequenceAccess.nativeCharSequenceAccess(), access);

        assertEquals(buildNumber('A', 'B', 'C', 'D'), access.getLong(TEST_STRING, 0));
        assertEquals((buildNumber('A', 'B', 'C', 'D') >>> 8) | (((long)'E') << 56), access.getLong(TEST_STRING, 1));

        assertEquals((int)buildNumber('A', 'B', '\0', '\0'), access.getInt(TEST_STRING, 0));
        assertEquals((int)(buildNumber('A', 'B', 'C', '\0') >>> 8), access.getInt(TEST_STRING, 1));
        assertEquals(unsignedInt((int)buildNumber('A', 'B', '\0', '\0')), access.getUnsignedInt(TEST_STRING, 0));
        assertEquals(unsignedInt((int)(buildNumber('A', 'B', 'C', '\0') >>> 8)), access.getUnsignedInt(TEST_STRING, 1));

        assertEquals((int)buildNumber('A', '\0', '\0', '\0'), access.getShort(TEST_STRING, 0));
        assertEquals((int)(short)(buildNumber('A', 'B', '\0', '\0') >>> 8), access.getShort(TEST_STRING, 1));
        assertEquals(unsignedShort((short)buildNumber('A', '\0', '\0', '\0')), access.getUnsignedShort(TEST_STRING, 0));
        assertEquals(unsignedShort((short)(buildNumber('A', 'B', '\0', '\0') >>> 8)), access.getUnsignedShort(TEST_STRING, 1));

        assertEquals((int)(byte)buildNumber('A', '\0', '\0', '\0'), access.getByte(TEST_STRING, 0));
        assertEquals((int)(byte)(buildNumber('A', '\0', '\0', '\0') >>> 8), access.getByte(TEST_STRING, 1));
        assertEquals(unsignedByte((byte)buildNumber('A', '\0', '\0', '\0')), access.getUnsignedByte(TEST_STRING, 0));
        assertEquals(unsignedByte((byte)(buildNumber('A', '\0', '\0', '\0') >>> 8)), access.getUnsignedByte(TEST_STRING, 1));
    }

    @Test
    public void testBigEndian() {
        assertEquals(LITTLE_ENDIAN, nativeOrder()); // ut is designed for LE machines

        final Access<CharSequence> access = CharSequenceAccess.charSequenceAccess(BIG_ENDIAN);
	assertNotSame(CharSequenceAccess.nativeCharSequenceAccess(), access);

        assertEquals(buildNumber('D', 'C', 'B', 'A'), access.getLong(TEST_STRING, 0));
        assertEquals((buildNumber('D', 'C', 'B', 'A') << 8) | ((byte)('E'>>>8)), access.getLong(TEST_STRING, 1));

        assertEquals((int)buildNumber('B', 'A', '\0', '\0'), access.getInt(TEST_STRING, 0));
        assertEquals((int)(buildNumber((char)('C'>>>8), 'B', 'A', '\0') >>> 8), access.getInt(TEST_STRING, 1));
        assertEquals(unsignedInt((int)buildNumber('B', 'A', '\0', '\0')), access.getUnsignedInt(TEST_STRING, 0));
        assertEquals(unsignedInt((int)(buildNumber((char)('C'>>>8), 'B', 'A', '\0') >>> 8)), access.getUnsignedInt(TEST_STRING, 1));

        assertEquals((int)buildNumber('A', '\0', '\0', '\0'), access.getShort(TEST_STRING, 0));
        assertEquals((int)(short)(buildNumber((char)('B'>>>8), 'A', '\0', '\0') >>> 8), access.getShort(TEST_STRING, 1));
        assertEquals(unsignedShort((short)buildNumber('A', '\0', '\0', '\0')), access.getUnsignedShort(TEST_STRING, 0));
        assertEquals(unsignedShort((short)(buildNumber((char)('B'>>>8), 'A', '\0', '\0') >>> 8)), access.getUnsignedShort(TEST_STRING, 1));

        assertEquals((int)(byte)(buildNumber('A', '\0', '\0', '\0') >> 8), access.getByte(TEST_STRING, 0));
        assertEquals((int)(byte)buildNumber('A', '\0', '\0', '\0'), access.getByte(TEST_STRING, 1));
        assertEquals(unsignedByte((byte)(buildNumber('A', '\0', '\0', '\0') >> 8)), access.getUnsignedByte(TEST_STRING, 0));
        assertEquals(unsignedByte((byte)buildNumber('A', '\0', '\0', '\0')), access.getUnsignedByte(TEST_STRING, 1));
    }
}

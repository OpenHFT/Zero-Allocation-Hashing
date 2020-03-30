package net.openhft.hashing;

import org.junit.Test;
import java.nio.ByteOrder;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

public class CompactLatin1CharSequenceAccessTest {
    static private final Access<byte[]> access = CompactLatin1CharSequenceAccess.INSTANCE;
    static private final byte[] b = { (byte)0xF1, (byte)0xE2, (byte)0xD3, (byte)0xC4, (byte)0xB5 };

    @Test
    public void testLE() {
        assumeTrue(ByteOrder.nativeOrder() == LITTLE_ENDIAN);

        assertEquals(    0xC400D300E200F1L, access.getLong(b, 0));
        assertEquals(0xB500C400D300E200L,   access.getLong(b, 1));

        assertEquals(                       0xE200F1,    access.getInt(b, 0));
        assertEquals(                       0xD300E200,  access.getInt(b, 1));
        assertEquals(Primitives.unsignedInt(0xE200F1),   access.getUnsignedInt(b, 0));
        assertEquals(Primitives.unsignedInt(0xD300E200), access.getUnsignedInt(b, 1));

        assertEquals(                         0xF1,    access.getShort(b, 0));
        assertEquals(             (int)(short)0xE200,  access.getShort(b, 1));
        assertEquals(Primitives.unsignedShort(0xF1),   access.getUnsignedShort(b, 0));
        assertEquals(Primitives.unsignedShort(0xE200), access.getUnsignedShort(b, 1));

        assertEquals(             (int)(byte)0xF1,  access.getByte(b, 0));
        assertEquals(                           0,  access.getByte(b, 1));
        assertEquals(Primitives.unsignedByte(0xF1), access.getUnsignedByte(b, 0));
        assertEquals(                           0,  access.getUnsignedByte(b, 1));
    }

    @Test
    public void testBE() {
        assumeTrue(ByteOrder.nativeOrder() == BIG_ENDIAN);

        assertEquals(0xF100E200D300C4L,   access.getLong(b, 0));
        assertEquals(0xF100E200D300C400L, access.getLong(b, 1));

        assertEquals(                       0xF100E2,    access.getInt(b, 0));
        assertEquals(                       0xF100E200,  access.getInt(b, 1));
        assertEquals(Primitives.unsignedInt(0xF100E2),   access.getUnsignedInt(b, 0));
        assertEquals(Primitives.unsignedInt(0xF100E200), access.getUnsignedInt(b, 1));

        assertEquals(                         0xF1,    access.getShort(b, 0));
        assertEquals(             (int)(short)0xF100,  access.getShort(b, 1));
        assertEquals(Primitives.unsignedShort(0xF1),   access.getUnsignedShort(b, 0));
        assertEquals(Primitives.unsignedShort(0xF100), access.getUnsignedShort(b, 1));

        assertEquals(                           0,  access.getByte(b, 0));
        assertEquals(             (int)(byte)0xF1,  access.getByte(b, 1));
        assertEquals(                           0,  access.getUnsignedByte(b, 0));
        assertEquals(Primitives.unsignedByte(0xF1), access.getUnsignedByte(b, 1));
    }
}

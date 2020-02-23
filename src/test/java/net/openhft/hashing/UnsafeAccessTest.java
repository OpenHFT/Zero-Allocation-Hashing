package net.openhft.hashing;

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

public class UnsafeAccessTest {
    @Test
    public void test() {
        assertNotSame("compile with jdk with Unsafe.getByte()", UnsafeAccess.INSTANCE, UnsafeAccess.OLD_INSTANCE);
        testUnsafeAccess(UnsafeAccess.INSTANCE);
        testUnsafeAccess(UnsafeAccess.OLD_INSTANCE);
    }

    private static void testUnsafeAccess(final Access<Object> unsafe) {
        {
            final long[] l = new long[]{0xFEDCBA9876543210L, 0x123456789ABCDEFL};
            assertEquals(l[0], unsafe.getLong(l, UnsafeAccess.LONG_BASE));
            assertEquals(l[1], unsafe.getLong(l, UnsafeAccess.LONG_BASE + 8));
        }

        {
            final int[] i = new int[]{0xFEDCBA98, 0x1234567};
            assertEquals(i[0], unsafe.getInt(i, UnsafeAccess.INT_BASE));
            assertEquals(i[1], unsafe.getInt(i, UnsafeAccess.INT_BASE + 4));
            assertEquals(Primitives.unsignedInt(i[0]), unsafe.getUnsignedInt(i, UnsafeAccess.INT_BASE));
            assertEquals(Primitives.unsignedInt(i[1]), unsafe.getUnsignedInt(i, UnsafeAccess.INT_BASE + 4));
        }

        {
            final short[] s = new short[]{(short) 0xF466, 0x227A};
            assertEquals((int) s[0], unsafe.getShort(s, UnsafeAccess.SHORT_BASE));
            assertEquals((int) s[1], unsafe.getShort(s, UnsafeAccess.SHORT_BASE + 2));
            assertEquals(Primitives.unsignedShort(s[0]), unsafe.getUnsignedShort(s, UnsafeAccess.SHORT_BASE));
            assertEquals(Primitives.unsignedShort(s[1]), unsafe.getUnsignedShort(s, UnsafeAccess.SHORT_BASE + 2));
        }

        {
            final byte[] b = new byte[]{(byte)0xF4, 0x5D};
            assertEquals((int) b[0], unsafe.getByte(b, UnsafeAccess.BYTE_BASE));
            assertEquals((int) b[1], unsafe.getByte(b, UnsafeAccess.BYTE_BASE + 1));
            assertEquals(Primitives.unsignedByte(b[0]), unsafe.getUnsignedByte(b, UnsafeAccess.BYTE_BASE));
            assertEquals(Primitives.unsignedByte(b[1]), unsafe.getUnsignedByte(b, UnsafeAccess.BYTE_BASE + 1));
        }
    }
}

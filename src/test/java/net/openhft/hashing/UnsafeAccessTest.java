package net.openhft.hashing;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assume.assumeTrue;

@RunWith(Parameterized.class)
public class UnsafeAccessTest {

    @Parameters
    public static Object[] data() {
        return new Object[] { UnsafeAccess.INSTANCE, UnsafeAccess.OLD_INSTANCE };
    }

    @Parameter
    public Access<Object> unsafe;

    @Test
    public void testInstance() {
        assertNotSame("compiled by jdk with Unsafe.getByte() method", UnsafeAccess.INSTANCE, UnsafeAccess.OLD_INSTANCE);
    }

    @Test
    public void testUnsafeAccess() {
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

    @Test
    public void testUnsafeAccessUnalignLE() {
        assumeTrue(nativeOrder() == LITTLE_ENDIAN);

        {
            final long[] l = new long[]{0xFEDCBA9876543210L, 0x123456789ABCDEFL};
            assertEquals(0xEFFEDCBA98765432L, unsafe.getLong(l, UnsafeAccess.LONG_BASE + 1));
        }

        {
            final int[] i = new int[]{0xFEDCBA98, 0x1234567};
            assertEquals(0x67FEDCBA, unsafe.getInt(i, UnsafeAccess.INT_BASE + 1));
            assertEquals(Primitives.unsignedInt(0x67FEDCBA), unsafe.getUnsignedInt(i, UnsafeAccess.INT_BASE + 1));
        }

        {
            final short[] s = new short[]{(short) 0xF466, 0x227A};
            assertEquals((int) 0x7AF4, unsafe.getShort(s, UnsafeAccess.SHORT_BASE + 1));
            assertEquals(Primitives.unsignedShort(0x7AF4), unsafe.getUnsignedShort(s, UnsafeAccess.SHORT_BASE + 1));
        }

        {
            final byte[] b = new byte[]{(byte)0xF4, 0x5D};
            assertEquals((int) 0x5D, unsafe.getByte(b, UnsafeAccess.BYTE_BASE + 1));
            assertEquals(Primitives.unsignedByte(0x5D), unsafe.getUnsignedByte(b, UnsafeAccess.BYTE_BASE + 1));
        }
    }

    @Test
    public void testUnsafeAccessUnalignBE() {
        assumeTrue(nativeOrder() == BIG_ENDIAN);

        {
            final long[] l = new long[]{0xFEDCBA9876543210L, 0x123456789ABCDEF0L};
            assertEquals(0xDCBA987654321012L, unsafe.getLong(l, UnsafeAccess.LONG_BASE + 1));
        }

        {
            final int[] i = new int[]{0xFEDCBA98, 0x12345670};
            assertEquals(0xDCBA9812, unsafe.getInt(i, UnsafeAccess.INT_BASE + 1));
            assertEquals(Primitives.unsignedInt(0xDCBA9812), unsafe.getUnsignedInt(i, UnsafeAccess.INT_BASE + 1));
        }

        {
            final short[] s = new short[]{(short) 0xF466, 0x227A};
            assertEquals((int) 0x6622, unsafe.getShort(s, UnsafeAccess.SHORT_BASE + 1));
            assertEquals(Primitives.unsignedShort(0x6622), unsafe.getUnsignedShort(s, UnsafeAccess.SHORT_BASE + 1));
        }

        {
            final byte[] b = new byte[]{(byte)0xF4, 0x5D};
            assertEquals((int) 0x5D, unsafe.getByte(b, UnsafeAccess.BYTE_BASE + 1));
            assertEquals(Primitives.unsignedByte(0x5D), unsafe.getUnsignedByte(b, UnsafeAccess.BYTE_BASE + 1));
        }
    }
}

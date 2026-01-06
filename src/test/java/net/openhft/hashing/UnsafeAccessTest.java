/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class UnsafeAccessTest {

    static Stream<Access<Object>> unsafeAccesses() {
        return Stream.of(UnsafeAccess.INSTANCE, UnsafeAccess.OLD_INSTANCE);
    }

    @Test
    public void testInstance() {
        assertNotSame(UnsafeAccess.INSTANCE, UnsafeAccess.OLD_INSTANCE, "compiled by jdk with Unsafe.getByte() method");
    }

    @ParameterizedTest(name = "{index}: {0}")
    @MethodSource("unsafeAccesses")
    public void testUnsafeAccess(Access<Object> unsafe) {
        {
            final long[] l = {0xFEDCBA9876543210L, 0x123456789ABCDEFL};
            assertEquals(l[0], unsafe.getLong(l, UnsafeAccess.LONG_BASE), "getLong aligned @0");
            assertEquals(l[1], unsafe.getLong(l, UnsafeAccess.LONG_BASE + 8), "getLong aligned @8");
        }

        {
            final int[] i = {0xFEDCBA98, 0x1234567};
            assertEquals(i[0], unsafe.getInt(i, UnsafeAccess.INT_BASE), "getInt aligned @0");
            assertEquals(i[1], unsafe.getInt(i, UnsafeAccess.INT_BASE + 4), "getInt aligned @4");
            assertEquals(Primitives.unsignedInt(i[0]), unsafe.getUnsignedInt(i, UnsafeAccess.INT_BASE), "getUnsignedInt aligned @0");
            assertEquals(Primitives.unsignedInt(i[1]), unsafe.getUnsignedInt(i, UnsafeAccess.INT_BASE + 4), "getUnsignedInt aligned @4");
        }

        {
            final short[] s = {(short) 0xF466, 0x227A};
            assertEquals(s[0], unsafe.getShort(s, UnsafeAccess.SHORT_BASE), "getShort aligned @0");
            assertEquals(s[1], unsafe.getShort(s, UnsafeAccess.SHORT_BASE + 2), "getShort aligned @2");
            assertEquals(Primitives.unsignedShort(s[0]), unsafe.getUnsignedShort(s, UnsafeAccess.SHORT_BASE), "getUnsignedShort aligned @0");
            assertEquals(Primitives.unsignedShort(s[1]), unsafe.getUnsignedShort(s, UnsafeAccess.SHORT_BASE + 2), "getUnsignedShort aligned @2");
        }

        {
            final byte[] b = {(byte) 0xF4, 0x5D};
            assertEquals(b[0], unsafe.getByte(b, UnsafeAccess.BYTE_BASE), "getByte aligned @0");
            assertEquals(b[1], unsafe.getByte(b, UnsafeAccess.BYTE_BASE + 1), "getByte aligned @1");
            assertEquals(Primitives.unsignedByte(b[0]), unsafe.getUnsignedByte(b, UnsafeAccess.BYTE_BASE), "getUnsignedByte aligned @0");
            assertEquals(Primitives.unsignedByte(b[1]), unsafe.getUnsignedByte(b, UnsafeAccess.BYTE_BASE + 1), "getUnsignedByte aligned @1");
        }
    }

    @ParameterizedTest(name = "{index}: {0}")
    @MethodSource("unsafeAccesses")
    public void testUnsafeAccessUnalignLE(Access<Object> unsafe) {
        assumeTrue(nativeOrder() == LITTLE_ENDIAN);

        {
            final long[] l = {0xFEDCBA9876543210L, 0x123456789ABCDEFL};
            assertEquals(0xEFFEDCBA98765432L, unsafe.getLong(l, UnsafeAccess.LONG_BASE + 1), "LE getLong unaligned +1");
        }

        {
            final int[] i = {0xFEDCBA98, 0x1234567};
            assertEquals(0x67FEDCBA, unsafe.getInt(i, UnsafeAccess.INT_BASE + 1), "LE getInt unaligned +1");
            assertEquals(Primitives.unsignedInt(0x67FEDCBA), unsafe.getUnsignedInt(i, UnsafeAccess.INT_BASE + 1), "LE getUnsignedInt unaligned +1");
        }

        {
            final short[] s = {(short) 0xF466, 0x227A};
            assertEquals(0x7AF4, unsafe.getShort(s, UnsafeAccess.SHORT_BASE + 1), "LE getShort unaligned +1");
            assertEquals(Primitives.unsignedShort(0x7AF4), unsafe.getUnsignedShort(s, UnsafeAccess.SHORT_BASE + 1), "LE getUnsignedShort unaligned +1");
        }

        {
            final byte[] b = {(byte) 0xF4, 0x5D};
            assertEquals(0x5D, unsafe.getByte(b, UnsafeAccess.BYTE_BASE + 1), "LE getByte +1");
            assertEquals(Primitives.unsignedByte(0x5D), unsafe.getUnsignedByte(b, UnsafeAccess.BYTE_BASE + 1), "LE getUnsignedByte +1");
        }
    }

    @ParameterizedTest(name = "{index}: {0}")
    @MethodSource("unsafeAccesses")
    public void testUnsafeAccessUnalignBE(Access<Object> unsafe) {
        assumeTrue(nativeOrder() == BIG_ENDIAN);

        {
            final long[] l = {0xFEDCBA9876543210L, 0x123456789ABCDEF0L};
            assertEquals(0xDCBA987654321012L, unsafe.getLong(l, UnsafeAccess.LONG_BASE + 1), "BE getLong unaligned +1");
        }

        {
            final int[] i = {0xFEDCBA98, 0x12345670};
            assertEquals(0xDCBA9812, unsafe.getInt(i, UnsafeAccess.INT_BASE + 1), "BE getInt unaligned +1");
            assertEquals(Primitives.unsignedInt(0xDCBA9812), unsafe.getUnsignedInt(i, UnsafeAccess.INT_BASE + 1), "BE getUnsignedInt unaligned +1");
        }

        {
            final short[] s = {(short) 0xF466, 0x227A};
            assertEquals(0x6622, unsafe.getShort(s, UnsafeAccess.SHORT_BASE + 1), "BE getShort unaligned +1");
            assertEquals(Primitives.unsignedShort(0x6622), unsafe.getUnsignedShort(s, UnsafeAccess.SHORT_BASE + 1), "BE getUnsignedShort unaligned +1");
        }

        {
            final byte[] b = {(byte) 0xF4, 0x5D};
            assertEquals(0x5D, unsafe.getByte(b, UnsafeAccess.BYTE_BASE + 1), "BE getByte +1");
            assertEquals(Primitives.unsignedByte(0x5D), unsafe.getUnsignedByte(b, UnsafeAccess.BYTE_BASE + 1), "BE getUnsignedByte +1");
        }
    }
}

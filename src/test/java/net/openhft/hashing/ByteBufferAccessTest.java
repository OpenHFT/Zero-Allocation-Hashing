/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class ByteBufferAccessTest {

    private static final byte[] SAMPLE = {
            (byte) 0x12, (byte) 0x34, (byte) 0x56, (byte) 0x78,
            (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0
    };

    @Test
    public void littleEndianAccessReadsExpectedValues() {
        ByteBuffer buffer = ByteBuffer.wrap(SAMPLE).order(LITTLE_ENDIAN);
        ByteBufferAccess access = ByteBufferAccess.INSTANCE;

        assertEquals(ByteOrder.LITTLE_ENDIAN, access.byteOrder(buffer), "LE byteOrder");
        assertEquals(0xF0DEBC9A78563412L, access.getLong(buffer, 0), "LE getLong @0");
        assertEquals(0xF0DEBC9AL, access.getUnsignedInt(buffer, 4), "LE getUnsignedInt @4");
        assertEquals(0x78563412, access.getInt(buffer, 0), "LE getInt @0");
        assertEquals(0xBC9A, access.getUnsignedShort(buffer, 4), "LE getUnsignedShort @4");
        assertEquals(0x5634, access.getShort(buffer, 1), "LE getShort @1");
        assertEquals(0xDE, access.getUnsignedByte(buffer, 6), "LE getUnsignedByte @6");
        assertEquals(-68, access.getByte(buffer, 5), "LE getByte @5");
    }

    @Test
    public void bigEndianAccessReadsExpectedValues() {
        ByteBuffer buffer = ByteBuffer.wrap(SAMPLE).order(BIG_ENDIAN);
        ByteBufferAccess access = ByteBufferAccess.INSTANCE;

        assertEquals(ByteOrder.BIG_ENDIAN, access.byteOrder(buffer), "BE byteOrder");
        assertEquals(0x123456789ABCDEF0L, access.getLong(buffer, 0), "BE getLong @0");
        assertEquals(0x12345678L, access.getUnsignedInt(buffer, 0), "BE getUnsignedInt @0");
        assertEquals((int) 0x9ABCDEF0L, access.getInt(buffer, 4), "BE getInt @4");
        assertEquals(0x5678, access.getUnsignedShort(buffer, 2), "BE getUnsignedShort @2");
        assertEquals(0x789A, access.getShort(buffer, 3), "BE getShort @3");
        assertEquals(0x34, access.getUnsignedByte(buffer, 1), "BE getUnsignedByte @1");
        assertEquals(-102, access.getByte(buffer, 4), "BE getByte @4");
    }

    @Test
    public void reverseAccessFlipsByteOrder() {
        ByteBuffer buffer = ByteBuffer.wrap(SAMPLE).order(LITTLE_ENDIAN);
        Access<ByteBuffer> reverse = ByteBufferAccess.INSTANCE.reverseAccess();

        assertEquals(ByteOrder.BIG_ENDIAN, reverse.byteOrder(buffer), "reverse byteOrder");
        assertEquals(0x123456789ABCDEF0L, reverse.getLong(buffer, 0), "reverse getLong @0");
        assertEquals(0x12345678L, reverse.getUnsignedInt(buffer, 0), "reverse getUnsignedInt @0");
        assertEquals((int) 0x9ABCDEF0L, reverse.getInt(buffer, 4), "reverse getInt @4");
        assertEquals(0x5678, reverse.getUnsignedShort(buffer, 2), "reverse getUnsignedShort @2");
        assertEquals(0x789A, reverse.getShort(buffer, 3), "reverse getShort @3");
        assertEquals(0x34, reverse.getUnsignedByte(buffer, 1), "reverse getUnsignedByte @1");
        assertEquals(-102, reverse.getByte(buffer, 4), "reverse getByte @4");
    }
}

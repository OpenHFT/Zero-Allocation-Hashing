/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

public class ForeignRawAccessTest {
    @Test
    public void matchesDirectBufferReads() {
        assumeTrue(RuntimeSupport.isAtLeast(22));
        final ForeignRawAccess access = ForeignRawAccess.INSTANCE;
        assertNotNull("FFM raw access should be available on JDK 22+", access);

        final ByteBuffer bb = ByteBuffer.allocateDirect(64).order(ByteOrder.nativeOrder());
        final byte[] data = new byte[64];
        new Random(7).nextBytes(data);
        bb.put(data);
        final long address = Util.getDirectBufferAddress(bb);

        for (int i = 0; i < 56; i++) {
            assertEquals(bb.getLong(i), access.getLong(null, address + i));
            assertEquals(bb.getInt(i), access.getInt(null, address + i));
            assertEquals(bb.getShort(i), access.getShort(null, address + i));
            assertEquals(data[i], access.getByte(null, address + i));
            assertEquals(data[i] & 0xFF, access.getUnsignedByte(null, address + i));
        }
    }

    @Test
    public void hashMemoryMatchesHashBytes() {
        assumeTrue(HeapAccess.RAW_MEMORY_AVAILABLE);
        final byte[] data = new byte[200];
        new Random(3).nextBytes(data);
        final ByteBuffer bb = ByteBuffer.allocateDirect(data.length);
        bb.put(data);
        final long address = Util.getDirectBufferAddress(bb);
        for (final LongHashFunction f : new LongHashFunction[] {
            LongHashFunction.xx(), LongHashFunction.xx3(), LongHashFunction.murmur_3(), LongHashFunction.wy_3()}) {
            assertEquals(f.hashBytes(data), f.hashMemory(address, data.length));
        }
        final LongTupleHashFunction t = LongTupleHashFunction.xx128();
        org.junit.Assert.assertArrayEquals(t.hashBytes(data), t.hashMemory(address, data.length));
    }
}

/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class ByteBufferAccess extends Access<ByteBuffer> {
    public static final ByteBufferAccess INSTANCE = new ByteBufferAccess();
    private static final Access<ByteBuffer> INSTANCE_REVERSE = Access.newDefaultReverseAccess(INSTANCE);

    private ByteBufferAccess() {
    }

    @Override
    public long getLong(ByteBuffer input, long offset) {
        return input.getLong((int) offset);
    }

    @Override
    public long getUnsignedInt(ByteBuffer input, long offset) {
        return Primitives.unsignedInt(getInt(input, offset));
    }

    @Override
    public int getInt(ByteBuffer input, long offset) {
        return input.getInt((int) offset);
    }

    @Override
    public int getUnsignedShort(ByteBuffer input, long offset) {
        return Primitives.unsignedShort(getShort(input, offset));
    }

    @Override
    public int getShort(ByteBuffer input, long offset) {
        return input.getShort((int) offset);
    }

    @Override
    public int getUnsignedByte(ByteBuffer input, long offset) {
        return Primitives.unsignedByte(getByte(input, offset));
    }

    @Override
    public int getByte(ByteBuffer input, long offset) {
        return input.get((int) offset);
    }

    @Override
    public ByteOrder byteOrder(ByteBuffer input) {
        return input.order();
    }

    @Override
    protected Access<ByteBuffer> reverseAccess() {
        return INSTANCE_REVERSE;
    }
}

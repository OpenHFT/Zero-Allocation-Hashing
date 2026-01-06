/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.nio.ByteOrder;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static net.openhft.hashing.UnsafeAccess.BYTE_BASE;

/**
 * Provides a {@link CharSequence}-style view over compact Latin-1 byte arrays. Each input byte is
 * treated as a UTF-16 code unit with a zero high byte. This access relies on {@link UnsafeAccess}
 * and only supports the platform native byte order.
 */
@ParametersAreNonnullByDefault
public class CompactLatin1CharSequenceAccess extends Access<byte[]> {
    @NotNull
    static final Access<byte[]> INSTANCE = new CompactLatin1CharSequenceAccess();

    @NotNull
    private static final Access<byte[]> INSTANCE_NON_NATIVE = Access.newDefaultReverseAccess(INSTANCE);

    @NotNull
    private static final UnsafeAccess UNSAFE = UnsafeAccess.INSTANCE;

    private static final long UNSAFE_IDX_ADJUST
        = BYTE_BASE * 2L + (ByteOrder.nativeOrder() == LITTLE_ENDIAN ? 1 : 0);
    private static final long ARRAY_IDX_ADJUST
        = ByteOrder.nativeOrder() == LITTLE_ENDIAN ? 1 : 0;

    private CompactLatin1CharSequenceAccess() {}

    /**
     * {@inheritDoc}
     */
    @Override
    public long getLong(final byte[] input, final long offset) {
        final long byteIdx = (offset + UNSAFE_IDX_ADJUST) >> 1;
        final long compact = UNSAFE.getUnsignedInt(input, byteIdx);
        long expanded = ((compact << 16) | compact) & 0xFFFF0000FFFFL;
        expanded = ((expanded << 8) | expanded) & 0xFF00FF00FF00FFL;
        if (((int)offset & 1) == 1) {
            return expanded << 8;
        }
        return expanded;
    }

    /** {@inheritDoc} */
    @Override
    public int getInt(final byte[] input, final long offset) {
        final long byteIdx = (offset + UNSAFE_IDX_ADJUST) >> 1;
        final int compact = UNSAFE.getShort(input, byteIdx) & 0xFFFF;
        final int expanded = ((compact << 8) | compact) & 0xFF00FF;
        if (((int)offset & 1) == 1) {
            return expanded << 8;
        }
        return expanded;
    }

    @Override
    public long getUnsignedInt(final byte[] input, final long offset) {
        final long byteIdx = (offset + UNSAFE_IDX_ADJUST) >> 1;
        final int compact = UNSAFE.getShort(input, byteIdx) & 0xFFFF;
        final long expanded = ((compact << 8) | compact) & 0xFF00FF;
        if (((int)offset & 1) == 1) {
            return expanded << 8;
        }
        return expanded;
    }

    /** {@inheritDoc} */
    @Override
    public int getShort(final byte[] input, final long offset) {
        if (((int)offset & 1) == 0) {
            final int byteIdx = (int)(offset >> 1);
            return (int)input[byteIdx] & 0xFF;
        } else {
            final int byteIdx = (int)((offset + ARRAY_IDX_ADJUST) >> 1);
            return (int)input[byteIdx] << 8;
        }
    }

    /** {@inheritDoc} */
    @Override
    public int getUnsignedShort(final byte[] input, final long offset) {
        if (((int)offset & 1) == 0) {
            final int byteIdx = (int)(offset >> 1);
            return (int)input[byteIdx] & 0xFF;
        } else {
            final int byteIdx = (int)((offset + ARRAY_IDX_ADJUST) >> 1);
            return ((int)input[byteIdx] & 0xFF) << 8;
        }
    }

    /** {@inheritDoc} */
    @Override
    public int getByte(final byte[] input, final long offset) {
        if (ARRAY_IDX_ADJUST == ((int)offset & 1)) {
            return 0;
        } else {
            return input[(int)(offset >> 1)];
        }
    }

    /** {@inheritDoc} */
    @Override
    public int getUnsignedByte(final byte[] input, final long offset) {
        if (ARRAY_IDX_ADJUST == ((int)offset & 1)) {
            return 0;
        } else {
            return (int)input[(int)(offset >> 1)] & 0xFF;
        }
    }

    @Override
    @NotNull
    public ByteOrder byteOrder(final byte[] input) {
        return UNSAFE.byteOrder(input);
    }

    @Override
    @NotNull
    protected Access<byte[]> reverseAccess() {
        return INSTANCE_NON_NATIVE;
    }
}

/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.nio.ByteOrder;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;

/**
 * {@link Access} implementation for UTF-16 {@link CharSequence} sources, handling both endian modes.
 */
public abstract class CharSequenceAccess extends Access<CharSequence> {

    /**
     * Returns the access implementation for the requested byte order.
     *
     * @param order desired byte order
     * @return access that reads chars using the specified order
     */
    static CharSequenceAccess charSequenceAccess(ByteOrder order) {
        return order == LITTLE_ENDIAN ?
                LittleEndianCharSequenceAccess.INSTANCE :
                BigEndianCharSequenceAccess.INSTANCE;
    }

    /**
     * @return access using the platform native byte order
     */
    static CharSequenceAccess nativeCharSequenceAccess() {
        return charSequenceAccess(ByteOrder.nativeOrder());
    }

    private static int ix(long offset) {
        return (int) (offset >> 1);
    }

    /**
     * Reads a 64-bit little- or big-endian value from a UTF-16 char sequence starting at {@code offset/2}.
     *
     * @param input    source sequence
     * @param offset   byte-aligned offset (each char = 2 bytes)
     * @param char0Off index offset for the first char
     * @param char1Off index offset for the second char
     * @param char2Off index offset for the third char
     * @param char3Off index offset for the fourth char
     * @param char4Off index offset for the fifth char (used when unaligned)
     * @param delta    adjustment applied when starting on an odd byte
     * @return 64-bit value read in the requested endianness
     */
    protected static long getLong(CharSequence input, long offset,
                                  int char0Off, int char1Off, int char2Off, int char3Off,
                                  int char4Off, int delta) {
        final int base = ix(offset);
        if (0 == ((int)offset & 1)) {
            final long char0 = input.charAt(base + char0Off);
            final long char1 = input.charAt(base + char1Off);
            final long char2 = input.charAt(base + char2Off);
            final long char3 = input.charAt(base + char3Off);
            return char0 | (char1 << 16) | (char2 << 32) | (char3 << 48);
        } else {
            final long char0 = input.charAt(base + char0Off + delta) >>> 8;
            final long char1 = input.charAt(base + char1Off + delta);
            final long char2 = input.charAt(base + char2Off + delta);
            final long char3 = input.charAt(base + char3Off + delta);
            final long char4 = input.charAt(base + char4Off);
            return char0 | (char1 << 8) | (char2 << 24) | (char3 << 40) | (char4 << 56);
        }
    }

    /**
     * Reads a 32-bit unsigned value from a UTF-16 char sequence starting at {@code offset/2}.
     *
     * @param input    source sequence
     * @param offset   byte-aligned offset (each char = 2 bytes)
     * @param char0Off index offset for the first char
     * @param char1Off index offset for the second char
     * @param char2Off index offset for the third char (when unaligned)
     * @param delta    adjustment applied when starting on an odd byte
     * @return 32-bit unsigned value
     */
    protected static long getUnsignedInt(CharSequence input, long offset,
                                         int char0Off, int char1Off, int char2Off, int delta) {
        final int base = ix(offset);
        if (0 == ((int)offset & 1)) {
            final long char0 = input.charAt(base + char0Off);
            final long char1 = input.charAt(base + char1Off);
            return char0 | (char1 << 16);
        } else {
            final long char0 = input.charAt(base + char0Off + delta) >>> 8;
            final long char1 = input.charAt(base + char1Off + delta);
            final long char2 = Primitives.unsignedByte(input.charAt(base + char2Off));
            return char0 | (char1 << 8) | (char2 << 24);
        }
    }

    /**
     * Reads a 16-bit unsigned value from a UTF-16 char sequence starting at {@code offset/2}.
     *
     * @param input    source sequence
     * @param offset   byte-aligned offset (each char = 2 bytes)
     * @param char1Off index offset for the second char when unaligned
     * @param delta    adjustment applied when starting on an odd byte
     * @return 16-bit unsigned value
     */
    protected static char getUnsignedShort(CharSequence input,
                                           long offset, int char1Off, int delta) {
        if (0 == ((int)offset & 1)) {
            return input.charAt(ix(offset));
        } else {
            final int base = ix(offset);
            final int char0 = input.charAt(base + delta) >>> 8;
            final int char1 = input.charAt(base + char1Off);
            return (char)(char0 | (char1 << 8));
        }
    }

    /**
     * Reads an unsigned byte from a UTF-16 char sequence starting at {@code offset/2}.
     *
     * @param input  source sequence
     * @param offset byte-aligned offset (each char = 2 bytes)
     * @param shift  shift (0 or 8) used to select the correct byte
     * @return unsigned byte value
     */
    protected static int getUnsignedByte(CharSequence input, long offset, int shift) {
        return Primitives.unsignedByte(input.charAt(ix(offset)) >> shift);
    }

    private CharSequenceAccess() {}

    @Override
    public int getInt(CharSequence input, long offset) {
        return (int) getUnsignedInt(input, offset);
    }

    @Override
    public int getShort(CharSequence input, long offset) {
        return (short)getUnsignedShort(input, offset);
    }

    @Override
    public int getByte(CharSequence input, long offset) {
        return (byte) getUnsignedByte(input, offset);
    }

    private static class LittleEndianCharSequenceAccess extends CharSequenceAccess {
        private static final CharSequenceAccess INSTANCE = new LittleEndianCharSequenceAccess();
        private static final Access<CharSequence> INSTANCE_REVERSE = Access.newDefaultReverseAccess(INSTANCE);

        private LittleEndianCharSequenceAccess() {}

        @Override
        public long getLong(CharSequence input, long offset) {
            return getLong(input, offset, 0, 1, 2, 3, 4, 0);
        }

        @Override
        public long getUnsignedInt(CharSequence input, long offset) {
            return getUnsignedInt(input, offset, 0, 1, 2, 0);
        }

        @Override
        public int getUnsignedShort(CharSequence input, long offset) {
            return getUnsignedShort(input, offset, 1, 0);
        }

        @Override
        public int getUnsignedByte(CharSequence input, long offset) {
            return getUnsignedByte(input, offset, ((int) offset & 1) << 3);
        }

        @Override
        public ByteOrder byteOrder(CharSequence input) {
            return LITTLE_ENDIAN;
        }

        @Override
        protected Access<CharSequence> reverseAccess() {
            return INSTANCE_REVERSE;
        }
    }

    private static class BigEndianCharSequenceAccess extends CharSequenceAccess {
        private static final CharSequenceAccess INSTANCE = new BigEndianCharSequenceAccess();
        private static final Access<CharSequence> INSTANCE_REVERSE = Access.newDefaultReverseAccess(INSTANCE);

        private BigEndianCharSequenceAccess() {}

        @Override
        public long getLong(CharSequence input, long offset) {
            return getLong(input, offset, 3, 2, 1, 0, 0, 1);
        }

        @Override
        public long getUnsignedInt(CharSequence input, long offset) {
            return getUnsignedInt(input, offset, 1, 0, 0, 1);
        }

        @Override
        public int getUnsignedShort(CharSequence input, long offset) {
            return getUnsignedShort(input, offset, 0, 1);
        }

        @Override
        public int getUnsignedByte(CharSequence input, long offset) {
            return getUnsignedByte(input, offset, (((int) offset & 1) ^ 1) << 3);
        }

        @Override
        public ByteOrder byteOrder(CharSequence input) {
            return BIG_ENDIAN;
        }

        @Override
        protected Access<CharSequence> reverseAccess() {
            return INSTANCE_REVERSE;
        }
    }
}

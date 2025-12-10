/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;

/**
 * Byte order helpers that avoid allocations while converting primitive widths.
 */
final class Primitives {

    /**
     * Prevents instantiation; all members are static helpers.
     */
    private Primitives() {
    }

    static final boolean NATIVE_LITTLE_ENDIAN = nativeOrder() == LITTLE_ENDIAN;

    static long unsignedInt(int i) {
        return i & 0xFFFFFFFFL;
    }

    static int unsignedShort(int s) {
        return s & 0xFFFF;
    }

    static int unsignedByte(int b) {
        return b & 0xFF;
    }

    private static final ByteOrderHelper H2LE = NATIVE_LITTLE_ENDIAN ? new ByteOrderHelper() : new ByteOrderHelperReverse();
    private static final ByteOrderHelper H2BE = NATIVE_LITTLE_ENDIAN ? new ByteOrderHelperReverse() : new ByteOrderHelper();

    /**
     * Adjusts a {@code long} from the JVM's native endian to little endian.
     */
    static long nativeToLittleEndian(final long v) {
        return H2LE.adjustByteOrder(v);
    }

    /**
     * Adjusts an {@code int} from the JVM's native endian to little endian.
     */
    static int nativeToLittleEndian(final int v) {
        return H2LE.adjustByteOrder(v);
    }

    /**
     * Adjusts a {@code short} from the JVM's native endian to little endian.
     */
    static short nativeToLittleEndian(final short v) {
        return H2LE.adjustByteOrder(v);
    }

    /**
     * Adjusts a {@code char} from the JVM's native endian to little endian.
     */
    static char nativeToLittleEndian(final char v) {
        return H2LE.adjustByteOrder(v);
    }

    /**
     * Adjusts a {@code long} from the JVM's native endian to big endian.
     */
    static long nativeToBigEndian(final long v) {
        return H2BE.adjustByteOrder(v);
    }

    /**
     * Adjusts an {@code int} from the JVM's native endian to big endian.
     */
    static int nativeToBigEndian(final int v) {
        return H2BE.adjustByteOrder(v);
    }

    /**
     * Adjusts a {@code short} from the JVM's native endian to big endian.
     */
    static short nativeToBigEndian(final short v) {
        return H2BE.adjustByteOrder(v);
    }

    /**
     * Adjusts a {@code char} from the JVM's native endian to big endian.
     */
    static char nativeToBigEndian(final char v) {
        return H2BE.adjustByteOrder(v);
    }

    private static class ByteOrderHelper {
        long adjustByteOrder(final long v) {
            return v;
        }

        int adjustByteOrder(final int v) {
            return v;
        }

        short adjustByteOrder(final short v) {
            return v;
        }

        char adjustByteOrder(final char v) {
            return v;
        }
    }

    private static class ByteOrderHelperReverse extends ByteOrderHelper {
        @Override
        long adjustByteOrder(final long v) {
            return Long.reverseBytes(v);
        }

        @Override
        int adjustByteOrder(final int v) {
            return Integer.reverseBytes(v);
        }

        @Override
        short adjustByteOrder(final short v) {
            return Short.reverseBytes(v);
        }

        @Override
        char adjustByteOrder(final char v) {
            return Character.reverseBytes(v);
        }
    }
}

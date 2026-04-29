/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;

final class Primitives {

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

    static long nativeToLittleEndian(final long v) {
        return H2LE.adjustByteOrder(v);
    }

    static int nativeToLittleEndian(final int v) {
        return H2LE.adjustByteOrder(v);
    }

    static short nativeToLittleEndian(final short v) {
        return H2LE.adjustByteOrder(v);
    }

    static char nativeToLittleEndian(final char v) {
        return H2LE.adjustByteOrder(v);
    }

    static long nativeToBigEndian(final long v) {
        return H2BE.adjustByteOrder(v);
    }

    static int nativeToBigEndian(final int v) {
        return H2BE.adjustByteOrder(v);
    }

    static short nativeToBigEndian(final short v) {
        return H2BE.adjustByteOrder(v);
    }

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
        long adjustByteOrder(final long v) {
            return Long.reverseBytes(v);
        }

        int adjustByteOrder(final int v) {
            return Integer.reverseBytes(v);
        }

        short adjustByteOrder(final short v) {
            return Short.reverseBytes(v);
        }

        char adjustByteOrder(final char v) {
            return Character.reverseBytes(v);
        }
    }
}

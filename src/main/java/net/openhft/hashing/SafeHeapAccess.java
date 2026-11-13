/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.nio.ByteOrder;

/**
 * Unsafe-free {@link Access} over primitive arrays, used on JDK 25+.
 *
 * <p>Offsets are logical byte offsets from the start of the array (base offset 0) and bytes are
 * presented in the platform native order, exactly as the Unsafe based access does. Reads allocate
 * nothing; wider reads are composed from {@link #getByte(Object, long)} by {@link Access}.
 */
final class SafeHeapAccess extends Access<Object> {
    static final SafeHeapAccess INSTANCE = new SafeHeapAccess();

    private static final boolean LE = Primitives.NATIVE_LITTLE_ENDIAN;
    private static final Access<Object> NON_NATIVE = Access.newDefaultReverseAccess(INSTANCE);

    private SafeHeapAccess() {}

    @Override
    public int getByte(final Object input, final long offset) {
        if (input instanceof byte[]) {
            return ((byte[]) input)[(int) offset];
        } else if (input instanceof long[]) {
            return (int) (element(((long[]) input)[(int) (offset >> 3)], offset, 8) & 0xFF);
        } else if (input instanceof int[]) {
            return (int) (element(((int[]) input)[(int) (offset >> 2)], offset, 4) & 0xFF);
        } else if (input instanceof char[]) {
            return (int) (element(((char[]) input)[(int) (offset >> 1)], offset, 2) & 0xFF);
        } else if (input instanceof short[]) {
            return (int) (element(((short[]) input)[(int) (offset >> 1)], offset, 2) & 0xFF);
        } else if (input instanceof boolean[]) {
            return ((boolean[]) input)[(int) offset] ? 1 : 0;
        }
        // Defensive guard; fail loudly rather than return a wrong hash. The library's own calls
        // only pass the six array types above:
        // - null (raw address): only reachable by a direct hash(null, access, addr, len) call
        //   with this access; the hashMemory entry points are routed to ForeignRawAccess.
        // - arbitrary objects (Pair-style, see Access#unsafe()): need Unsafe field offsets, so
        //   they can only arrive through such direct calls as well.
        // - float[]/double[]: no hashFloats/hashDoubles exist today. If they are added, extend
        //   this method (via Float.floatToRawIntBits/Double.doubleToRawLongBits).
        throw new IllegalArgumentException("Unsupported input without Unsafe: "
            + (input == null ? "null (raw memory)" : input.getClass().getName()));
    }

    private static long element(final long value, final long offset, final int width) {
        final int pos = (int) (offset & (width - 1));
        return value >>> ((LE ? pos : width - 1 - pos) << 3);
    }

    @Override
    public ByteOrder byteOrder(final Object input) {
        return ByteOrder.nativeOrder();
    }

    @Override
    protected Access<Object> reverseAccess() {
        return NON_NATIVE;
    }
}

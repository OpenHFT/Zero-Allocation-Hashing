/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

/**
 * One-time selection of the array access backend.
 *
 * <p>When {@link RuntimeSupport#useUnsafeAccess()} is false (JDK 25+ or forced by property) this
 * class never touches {@link UnsafeAccess}, so {@code sun.misc.Unsafe} is never instantiated.
 * Raw-memory and {@code DirectBuffer} fast paths are only available with Unsafe.
 */
final class HeapAccess {
    static final boolean UNSAFE_ENABLED = RuntimeSupport.useUnsafeAccess();

    static final Access<Object> ACCESS;

    /** Access for absolute native addresses, or {@code null} if raw memory is unsupported. */
    static final Access<Object> RAW_MEMORY_ACCESS;
    static final boolean RAW_MEMORY_AVAILABLE;

    static final long BOOLEAN_BASE;
    static final long BYTE_BASE;
    static final long CHAR_BASE;
    static final long SHORT_BASE;
    static final long INT_BASE;
    static final long LONG_BASE;

    static final byte TRUE_BYTE_VALUE;
    static final byte FALSE_BYTE_VALUE;

    static {
        if (UNSAFE_ENABLED) {
            ACCESS = UnsafeAccess.INSTANCE;
            RAW_MEMORY_ACCESS = UnsafeAccess.INSTANCE;
            BOOLEAN_BASE = UnsafeAccess.BOOLEAN_BASE;
            BYTE_BASE = UnsafeAccess.BYTE_BASE;
            CHAR_BASE = UnsafeAccess.CHAR_BASE;
            SHORT_BASE = UnsafeAccess.SHORT_BASE;
            INT_BASE = UnsafeAccess.INT_BASE;
            LONG_BASE = UnsafeAccess.LONG_BASE;
            TRUE_BYTE_VALUE = UnsafeAccess.TRUE_BYTE_VALUE;
            FALSE_BYTE_VALUE = UnsafeAccess.FALSE_BYTE_VALUE;
        } else {
            ACCESS = SafeHeapAccess.INSTANCE;
            RAW_MEMORY_ACCESS = ForeignRawAccess.INSTANCE;
            BOOLEAN_BASE = 0L;
            BYTE_BASE = 0L;
            CHAR_BASE = 0L;
            SHORT_BASE = 0L;
            INT_BASE = 0L;
            LONG_BASE = 0L;
            TRUE_BYTE_VALUE = 1;
            FALSE_BYTE_VALUE = 0;
        }
    }

    static {
        RAW_MEMORY_AVAILABLE = RAW_MEMORY_ACCESS != null;
    }

    private HeapAccess() {}

    /** Returns the access for {@code hashMemory}; fails fast if no raw memory backend exists. */
    static Access<Object> rawMemoryAccess() {
        if (RAW_MEMORY_ACCESS == null) {
            throw new UnsupportedOperationException(
                "Raw memory access needs sun.misc.Unsafe (JDK < 25) or the FFM API (JDK 22+), "
                    + "neither is usable on this JVM");
        }
        return RAW_MEMORY_ACCESS;
    }

    /** Guards {@link Access#unsafe()}: object plus field-offset access needs real Unsafe. */
    static void requireUnsafe() {
        if (!UNSAFE_ENABLED) {
            throw new UnsupportedOperationException(
                "Access.unsafe() requires sun.misc.Unsafe, which is not used on this JVM");
        }
    }
}

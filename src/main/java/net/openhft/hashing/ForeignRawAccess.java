/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Method;
import java.nio.ByteOrder;

/**
 * Raw native-address {@link Access} built on the Foreign Function and Memory API (final in
 * JDK 22), used instead of {@code sun.misc.Unsafe} where Unsafe is not used.
 *
 * <p>The API is reached through method handles so that the library still compiles for Java 8 and
 * ships as a single artifact. The handles are bound to one process-wide segment spanning the whole
 * address space ({@code MemorySegment.NULL.reinterpret(Long.MAX_VALUE)}), so the "offset" of an
 * access is the absolute address, exactly like {@code Unsafe.getLong(null, address)}. The handles
 * are static finals and so are constant-folded by the JIT; reads allocate nothing.
 *
 * <p>{@code reinterpret} is a restricted method: JDK 24+ prints a one-off warning unless
 * {@code --enable-native-access=ALL-UNNAMED} is given. If the API is missing or refused,
 * {@link #INSTANCE} is {@code null} and raw memory stays unsupported.
 *
 * <p>The {@code input} argument is ignored and must be {@code null}; this class is not exposed
 * publicly because object plus field-offset access (see {@link Access#unsafe()}) cannot be
 * expressed with it. Addresses at or above {@code 2^63} are not supported.
 */
final class ForeignRawAccess extends Access<Object> {
    static final ForeignRawAccess INSTANCE;

    private static final MethodHandle GET_LONG;
    private static final MethodHandle GET_INT;
    private static final MethodHandle GET_SHORT;
    private static final MethodHandle GET_BYTE;
    private static final Access<Object> NON_NATIVE;

    static {
        MethodHandle l = null;
        MethodHandle i = null;
        MethodHandle s = null;
        MethodHandle b = null;
        if (RuntimeSupport.isAtLeast(22)) {
            try {
                final Class<?> segmentClass = Class.forName("java.lang.foreign.MemorySegment");
                final Class<?> layouts = Class.forName("java.lang.foreign.ValueLayout");
                final Object global = segmentClass.getMethod("reinterpret", long.class)
                    .invoke(segmentClass.getField("NULL").get(null), Long.MAX_VALUE);
                l = bind(segmentClass, layouts, global, "JAVA_LONG_UNALIGNED", "OfLong", long.class);
                i = bind(segmentClass, layouts, global, "JAVA_INT_UNALIGNED", "OfInt", int.class);
                s = bind(segmentClass, layouts, global, "JAVA_SHORT_UNALIGNED", "OfShort", short.class);
                b = bind(segmentClass, layouts, global, "JAVA_BYTE", "OfByte", byte.class);
            } catch (final Throwable ignore) {
                l = null;
            }
        }
        final boolean ok = l != null && i != null && s != null && b != null;
        GET_LONG = ok ? l : null;
        GET_INT = ok ? i : null;
        GET_SHORT = ok ? s : null;
        GET_BYTE = ok ? b : null;
        INSTANCE = ok ? new ForeignRawAccess() : null;
        NON_NATIVE = ok ? Access.newDefaultReverseAccess(INSTANCE) : null;
    }

    private ForeignRawAccess() {}

    /** Returns a {@code (long address) -> value} handle reading with the given native layout. */
    private static MethodHandle bind(final Class<?> segmentClass, final Class<?> layouts,
                                     final Object global, final String layoutField,
                                     final String layoutType, final Class<?> valueType)
        throws ReflectiveOperationException {
        final Object layout = layouts.getField(layoutField).get(null);
        final Class<?> layoutClass = Class.forName("java.lang.foreign.ValueLayout$" + layoutType);
        final Method get = segmentClass.getMethod("get", layoutClass, long.class);
        final MethodHandle handle = MethodHandles.lookup().unreflect(get);
        return MethodHandles.insertArguments(handle, 0, global, layout)
            .asType(MethodType.methodType(valueType, long.class));
    }

    @Override
    public long getLong(final Object input, final long offset) {
        try {
            return (long) GET_LONG.invokeExact(offset);
        } catch (final Throwable t) {
            throw rethrow(t);
        }
    }

    @Override
    public long getUnsignedInt(final Object input, final long offset) {
        return Primitives.unsignedInt(getInt(input, offset));
    }

    @Override
    public int getInt(final Object input, final long offset) {
        try {
            return (int) GET_INT.invokeExact(offset);
        } catch (final Throwable t) {
            throw rethrow(t);
        }
    }

    @Override
    public int getUnsignedShort(final Object input, final long offset) {
        return Primitives.unsignedShort(getShort(input, offset));
    }

    @Override
    public int getShort(final Object input, final long offset) {
        try {
            return (short) GET_SHORT.invokeExact(offset);
        } catch (final Throwable t) {
            throw rethrow(t);
        }
    }

    @Override
    public int getUnsignedByte(final Object input, final long offset) {
        return Primitives.unsignedByte(getByte(input, offset));
    }

    @Override
    public int getByte(final Object input, final long offset) {
        try {
            return (byte) GET_BYTE.invokeExact(offset);
        } catch (final Throwable t) {
            throw rethrow(t);
        }
    }

    private static RuntimeException rethrow(final Throwable t) {
        if (t instanceof RuntimeException) {
            return (RuntimeException) t;
        } else if (t instanceof Error) {
            throw (Error) t;
        }
        return new IllegalStateException(t);
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

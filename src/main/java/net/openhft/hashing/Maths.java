/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.jetbrains.annotations.NotNull;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Method;

/**
 * Internal maths helpers for hashing implementations. Chooses a JDK-specific implementation at
 * class-load time to take advantage of {@code Math.multiplyHigh} when available while keeping a
 * zero-allocation fallback for older runtimes.
 */
class Maths {
    @NotNull
    private static final Maths INSTANCE = createInstance();

    /**
     * Selects the best available implementation. On JDK 9+ this wraps the intrinsified
     * {@code Math.multiplyHigh(int,int)}; otherwise it falls back to the pure Java implementation.
     */
    private static Maths createInstance() {
        try {
            Method multiplyHigh = Math.class.getDeclaredMethod("multiplyHigh", int.class, int.class);
            MethodHandle multiplyHighMH = MethodHandles.lookup().unreflect(multiplyHigh);
            return new MathsJDK9(multiplyHighMH);
        } catch (final Throwable ignore) {
            return new Maths();
        }
    }

    public static long unsignedLongMulXorFold(final long lhs, final long rhs) {
        return INSTANCE.unsignedLongMulXorFoldImp(lhs, rhs);
    }
    public static long unsignedLongMulHigh(final long lhs, final long rhs) {
        return INSTANCE.unsignedLongMulHighImp(lhs, rhs);
    }

    long unsignedLongMulXorFoldImp(final long lhs, final long rhs) {
        // The Grade School method of multiplication is a hair faster in Java, primarily used here
        // because the implementation is simpler.
        final long lhs_l = lhs & 0xFFFFFFFFL;
        final long lhs_h = lhs >>> 32;
        final long rhs_l = rhs & 0xFFFFFFFFL;
        final long rhs_h = rhs >>> 32;
        final long lo_lo = lhs_l * rhs_l;
        final long hi_lo = lhs_h * rhs_l;
        final long lo_hi = lhs_l * rhs_h;
        final long hi_hi = lhs_h * rhs_h;

        // Add the products together. This will never overflow.
        final long cross = (lo_lo >>> 32) + (hi_lo & 0xFFFFFFFFL) + lo_hi;
        final long upper = (hi_lo >>> 32) + (cross >>> 32) + hi_hi;
        final long lower = (cross << 32) | (lo_lo & 0xFFFFFFFFL);
        return lower ^ upper;
    }

    long unsignedLongMulHighImp(final long lhs, final long rhs) {
        // The Grade School method of multiplication is a hair faster in Java, primarily used here
        // because the implementation is simpler.
        final long lhs_l = lhs & 0xFFFFFFFFL;
        final long lhs_h = lhs >>> 32;
        final long rhs_l = rhs & 0xFFFFFFFFL;
        final long rhs_h = rhs >>> 32;
        final long lo_lo = lhs_l * rhs_l;
        final long hi_lo = lhs_h * rhs_l;
        final long lo_hi = lhs_l * rhs_h;
        final long hi_hi = lhs_h * rhs_h;

        // Add the products together. This will never overflow.
        final long cross = (lo_lo >>> 32) + (hi_lo & 0xFFFFFFFFL) + lo_hi;
        final long upper = (hi_lo >>> 32) + (cross >>> 32) + hi_hi;
        return upper;
    }
}

class MathsJDK9 extends Maths {
    private final MethodHandle multiplyHighMH;

    public MathsJDK9(MethodHandle multiplyHighMH) {
        this.multiplyHighMH = multiplyHighMH;
    }

    // Math.multiplyHigh() is intrinsified from JDK 10. But JDK 9 is out of life, we always prefer
    // this version to the scalar one.
    @Override
    long unsignedLongMulXorFoldImp(final long lhs, final long rhs) {
        final long upper = invokeExact(lhs, rhs) + ((lhs >> 63) & rhs) + ((rhs >> 63) & lhs);
        final long lower = lhs * rhs;
        return lower ^ upper;
    }
    @Override
    long unsignedLongMulHighImp(final long lhs, final long rhs) {
        return invokeExact(lhs, rhs) + ((lhs >> 63) & rhs) + ((rhs >> 63) & lhs);
    }

    private long invokeExact(long lhs, long rhs) {
        try {
            return (long) multiplyHighMH.invokeExact(lhs, rhs);
        } catch (Throwable e) {
            throw new AssertionError(e);
        }
    }
}

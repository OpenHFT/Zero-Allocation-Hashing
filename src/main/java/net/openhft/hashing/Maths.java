package net.openhft.hashing;

import org.jetbrains.annotations.NotNull;

class Maths {
    @NotNull
    private static final Maths INSTANCE;

    static {
        boolean hasMultiplyHigh = true;
        try {
          Math.multiplyHigh(0, 0);
        } catch (final Throwable ignore) {
          hasMultiplyHigh = false;
        }
        INSTANCE = hasMultiplyHigh ? new MathsJDK9() : new Maths();
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
    // Math.multiplyHigh() is intrinsified from JDK 10. But JDK 9 is out of life, we always prefer
    // this version to the scalar one.
    @Override
    long unsignedLongMulXorFoldImp(final long lhs, final long rhs) {
        final long upper = Math.multiplyHigh(lhs, rhs) + ((lhs >> 63) & rhs) + ((rhs >> 63) & lhs);
        final long lower = lhs * rhs;
        return lower ^ upper;
    }
    @Override
    long unsignedLongMulHighImp(final long lhs, final long rhs) {
        return Math.multiplyHigh(lhs, rhs) + ((lhs >> 63) & rhs) + ((rhs >> 63) & lhs);
    }
}

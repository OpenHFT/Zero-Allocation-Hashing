package net.openhft.hashing;

import org.jetbrains.annotations.Nullable;
import org.jetbrains.annotations.NotNull;
import javax.annotation.ParametersAreNonnullByDefault;

// An internal helper class for casting LongTupleHashFunction as LongHashFunction

@ParametersAreNonnullByDefault
abstract class DualHashFunction extends LongTupleHashFunction {
    private static final long serialVersionUID = 0L;

    protected abstract long dualHashLong(long input, @Nullable long[] result);
    @Override
    public void hashLong(final long input, final long[] result) {
        dualHashLong(input, result);
    }

    protected abstract long dualHashInt(int input, @Nullable long[] result);
    @Override
    public void hashInt(final int input, final long[] result) {
        dualHashInt(input, result);
    }

    protected abstract long dualHashShort(short input, @Nullable long[] result);
    @Override
    public void hashShort(final short input, final long[] result) {
        dualHashShort(input, result);
    }

    protected abstract long dualHashChar(char input, @Nullable long[] result);
    @Override
    public void hashChar(final char input, final long[] result) {
        dualHashChar(input, result);
    }

    protected abstract long dualHashByte(byte input, @Nullable long[] result);
    @Override
    public void hashByte(final byte input, final long[] result) {
        dualHashByte(input, result);
    }

    protected abstract long dualHashVoid(@Nullable long[] result);
    @Override
    public void hashVoid(final long[] result) {
        dualHashVoid(result);
    }

    protected abstract <T> long dualHash(@Nullable T input, Access<T> access, long off, long len, @Nullable long[] result);
    @Override
    public <T> void hash(@Nullable final T input, final Access<T> access, final long off, final long len, final long[] result) {
        dualHash(input, access, off, len, result);
    }

    @Nullable
    private transient volatile LongHashFunction longHashFunction = null;

    @NotNull
    protected LongHashFunction asLongHashFunction() {
        if (null == longHashFunction) {
            // LongTupleHashFunction and LongHashFunction are stateless objects after construction
            // so when caching the instance, we don't care the concurrence,
            // and this function is still thread safe.
            longHashFunction = new LongHashFunction() {
                @Override
                public long hashLong(final long input) {
                    return dualHashLong(input, null);
                }

                @Override
                public long hashInt(final int input) {
                    return dualHashInt(input, null);
                }

                @Override
                public long hashShort(final short input) {
                    return dualHashShort(input, null);
                }

                @Override
                public long hashChar(final char input) {
                    return dualHashChar(input, null);
                }

                @Override
                public long hashByte(final byte input) {
                    return dualHashByte(input, null);
                }

                @Override
                public long hashVoid() {
                    return dualHashVoid(null);
                }

                @Override
                public <T> long hash(@Nullable final T input, final Access<T> access, final long off, final long len) {
                    return dualHash(input, access, off, len, null);
                }
            };
        }
        return longHashFunction;
    }
}

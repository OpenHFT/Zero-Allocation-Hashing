package net.openhft.hashing;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import sun.nio.ch.DirectBuffer;

import java.io.Serializable;
import java.nio.ByteBuffer;

import static net.openhft.hashing.CharSequenceAccess.nativeCharSequenceAccess;
import static net.openhft.hashing.UnsafeAccess.*;
import static net.openhft.hashing.Util.*;

@ParametersAreNonnullByDefault
public abstract class LongTupleHashFunction implements Serializable {
    private static final long serialVersionUID = 0L;

    // Implementations
    //

    /**
     * Returns a hash function implementing
     * <a href="https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp">MurmurHash3
     * algorithm</a> without seed values. This implementation produces equal results for equal input
     * on platforms with different {@link ByteOrder}, but is slower on big-endian platforms than on
     * little-endian.
     *
     * @see #murmur_3(long)
     */
    @NotNull
    public static LongTupleHashFunction murmur_3() {
        return MurmurHash_3.asLongTupleHashFunctionWithoutSeed();
    }

    /**
     * Returns a hash function implementing
     * <a href="https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp">MurmurHash3
     * algorithm</a> with the given seed value. This implementation produces equal results for equal
     * input on platforms with different {@link ByteOrder}, but is slower on big-endian platforms
     * than on little-endian.
     *
     * @see #murmur_3()
     */
    @NotNull
    public static LongTupleHashFunction murmur_3(final long seed) {
        return MurmurHash_3.asLongTupleHashFunctionWithSeed(seed);
    }

    // Public API
    //

    /**
     * Returns the number of bits in a result array; a positive multiple of 8.
     */
    public abstract int bitsLength();

    /**
     * Returns an empty result array
     */
    @NotNull
    public long[] newResultArray() {
        return new long[(bitsLength() + 63) / 64];
    }

    public abstract void hashLong(long input, long[] result);
    @NotNull
    public long[] hashLong(final long input) {
        final long[] result = newResultArray();
        hashLong(input, result);
        return result;
    }

    public abstract void hashInt(int input, long[] result);
    @NotNull
    public long[] hashInt(final int input) {
        final long[] result = newResultArray();
        hashInt(input, result);
        return result;
    }

    public abstract void hashShort(short input, long[] result);
    @NotNull
    public long[] hashShort(final short input) {
        final long[] result = newResultArray();
        hashShort(input, result);
        return result;
    }

    public abstract void hashChar(char input, long[] result);
    @NotNull
    public long[] hashChar(final char input) {
        final long[] result = newResultArray();
        hashChar(input, result);
        return result;
    }

    public abstract void hashByte(byte input, long[] result);
    @NotNull
    public long[] hashByte(final byte input) {
        final long[] result = newResultArray();
        hashByte(input, result);
        return result;
    }

    public abstract void hashVoid(long[] result);
    @NotNull
    public long[] hashVoid() {
        final long[] result = newResultArray();
        hashVoid(result);
        return result;
    }

    public abstract <T> void hash(@Nullable T input, Access<T> access, long off, long len, long[] result);
    @NotNull
    public <T> long[] hash(@Nullable final T input, final Access<T> access, final long off, final long len) {
        final long[] result = newResultArray();
        hash(input, access, off, len, result);
        return result;
    }

    public void hashBoolean(final boolean input, final long[] result) {
        hashByte(input ? TRUE_BYTE_VALUE : FALSE_BYTE_VALUE, result);
    }
    @NotNull
    public long[] hashBoolean(final boolean input) {
        final long[] result = newResultArray();
        hashByte(input ? TRUE_BYTE_VALUE : FALSE_BYTE_VALUE, result);
        return result;
    }

    public void hashBooleans(final boolean[] input, final long[] result) {
        unsafeHash(this, input, BOOLEAN_BASE, input.length, result);
    }
    @NotNull
    public long[] hashBooleans(final boolean[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, BOOLEAN_BASE, input.length, result);
        return result;
    }

    public void hashBooleans(final boolean[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, BOOLEAN_BASE + off, len, result);
    }
    @NotNull
    public long[] hashBooleans(final boolean[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, BOOLEAN_BASE + off, len, result);
        return result;
    }

    public void hashBytes(final byte[] input, final long[] result) {
        unsafeHash(this, input, BYTE_BASE, input.length, result);
    }
    @NotNull
    public long[] hashBytes(final byte[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, BYTE_BASE, input.length, result);
        return result;
    }

    public void hashBytes(final byte[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, BYTE_BASE + off, len, result);
    }
    @NotNull
    public long[] hashBytes(final byte[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, BYTE_BASE + off, len, result);
        return result;
    }

    public void hashBytes(final ByteBuffer input, final long[] result) {
        hashByteBuffer(this, input, input.position(), input.remaining(), result);
    }
    @NotNull
    public long[] hashBytes(final ByteBuffer input) {
        final long[] result = newResultArray();
        hashByteBuffer(this, input, input.position(), input.remaining(), result);
        return result;
    }

    public void hashBytes(final ByteBuffer input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.capacity(), off, len);
        hashByteBuffer(this, input, off, len, result);
    }
    @NotNull
    public long[] hashBytes(final ByteBuffer input, final int off, final int len) {
        checkArrayOffs(input.capacity(), off, len);
        final long[] result = newResultArray();
        hashByteBuffer(this, input, off, len, result);
        return result;
    }

    public void hashMemory(final long address, final long len, final long[] result) {
        unsafeHash(this, null, address, len, result);
    }
    @NotNull
    public long[] hashMemory(final long address, final long len) {
        final long[] result = newResultArray();
        unsafeHash(this, null, address, len, result);
        return result;
    }

    public void hashChars(final char[] input, final long[] result) {
        unsafeHash(this, input, CHAR_BASE, input.length * 2L, result);
    }
    @NotNull
    public long[] hashChars(final char[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, CHAR_BASE, input.length * 2L, result);
        return result;
    }

    public void hashChars(final char[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, CHAR_BASE + (off * 2L), len * 2L, result);
    }
    @NotNull
    public long[] hashChars(final char[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, CHAR_BASE + (off * 2L), len * 2L, result);
        return result;
    }

    public void hashChars(final String input, final long[] result) {
        VALID_STRING_HASH.hash(input, this, 0, input.length(), result);
    }
    @NotNull
    public long[] hashChars(final String input) {
        final long[] result = newResultArray();
        VALID_STRING_HASH.hash(input, this, 0, input.length(), result);
        return result;
    }

    public void hashChars(final String input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length(), off, len);
        VALID_STRING_HASH.hash(input, this, off, len, result);
    }
    @NotNull
    public long[] hashChars(final String input, final int off, final int len) {
        checkArrayOffs(input.length(), off, len);
        final long[] result = newResultArray();
        VALID_STRING_HASH.hash(input, this, off, len, result);
        return result;
    }

    public <T extends CharSequence> void hashChars(final T input, final long[] result) {
        hashNativeChars(this, input, 0, input.length(), result);
    }
    @NotNull
    public <T extends CharSequence> long[] hashChars(final T input) {
        final long[] result = newResultArray();
        hashNativeChars(this, input, 0, input.length(), result);
        return result;
    }

    public <T extends CharSequence> void hashChars(final T input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length(), off, len);
        hashNativeChars(this, input, off, len, result);
    }
    @NotNull
    public <T extends CharSequence> long[] hashChars(final T input, final int off, final int len) {
        checkArrayOffs(input.length(), off, len);
        final long[] result = newResultArray();
        hashNativeChars(this, input, off, len, result);
        return result;
    }

    public void hashShorts(final short[] input, final long[] result) {
        unsafeHash(this, input, SHORT_BASE, input.length * 2L, result);
    }
    @NotNull
    public long[] hashShorts(final short[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, SHORT_BASE, input.length * 2L, result);
        return result;
    }

    public void hashShorts(final short[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, SHORT_BASE + (off * 2L), len * 2L, result);
    }
    @NotNull
    public long[] hashShorts(final short[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, SHORT_BASE + (off * 2L), len * 2L, result);
        return result;
    }

    public void hashInts(final int[] input, final long[] result) {
        unsafeHash(this, input, INT_BASE, input.length * 4L, result);
    }
    @NotNull
    public long[] hashInts(final int[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, INT_BASE, input.length * 4L, result);
        return result;
    }

    public void hashInts(final int[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, INT_BASE + (off * 4L), len * 4L, result);
    }
    @NotNull
    public long[] hashInts(final int[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, INT_BASE + (off * 4L), len * 4L, result);
        return result;
    }

    public void hashLongs(final long[] input, final long[] result) {
        unsafeHash(this, input, LONG_BASE, input.length * 8L, result);
    }
    @NotNull
    public long[] hashLongs(final long[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, LONG_BASE, input.length * 8L, result);
        return result;
    }

    public void hashLongs(final long[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, LONG_BASE + (off * 8L), len * 8L, result);
    }
    @NotNull
    public long[] hashLongs(final long[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, LONG_BASE + (off * 8L), len * 8L, result);
        return result;
    }

    // Internal helper
    //
    @NotNull
    private static final Access<Object> OBJECT_ACCESS = UnsafeAccess.INSTANCE;
    @NotNull
    private static final Access<CharSequence> CHAR_SEQ_ACCESS = nativeCharSequenceAccess();
    @NotNull
    private static final Access<ByteBuffer> BYTE_BUF_ACCESS = ByteBufferAccess.INSTANCE;

    private static void unsafeHash(final LongTupleHashFunction f, @Nullable final Object input,
                    final long off, final long len, final long[] result) {
        f.hash(input, OBJECT_ACCESS, off, len, result);
    }

    private static void hashByteBuffer(final LongTupleHashFunction f, final ByteBuffer input,
                    final int off, final int len, final long[] result) {
        if (input.hasArray()) {
            unsafeHash(f, input.array(), BYTE_BASE + input.arrayOffset() + off, len, result);
        } else if (input instanceof DirectBuffer) {
            unsafeHash(f, null, ((DirectBuffer) input).address() + off, len, result);
        } else {
            f.hash(input, BYTE_BUF_ACCESS, off, len, result);
        }
    }

    static void hashNativeChars(final LongTupleHashFunction f, final CharSequence input,
                    final int off, final int len, final long[] result) {
        f.hash(input, CHAR_SEQ_ACCESS, off * 2L, len * 2L, result);
    }

}

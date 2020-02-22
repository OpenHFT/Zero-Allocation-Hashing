package net.openhft.hashing;

import org.jetbrains.annotations.NotNull;
import sun.nio.ch.DirectBuffer;

import java.nio.ByteBuffer;

import static net.openhft.hashing.CharSequenceAccess.nativeCharSequenceAccess;
import static net.openhft.hashing.UnsafeAccess.*;

public abstract class LongTupleHashFunction extends LongHashFunction {
    private static final long serialVersionUID = 0L;

    public abstract int bits();
    public long[] newLongTuple() {
	return new long[(bits() + 63) / 64];
    }
    public long highMask() {
        final int bitsInHighM1 = (bits() - 1) & 63;
        return ((1L << bitsInHighM1) << 1) - 1;
    }

    /**
     * Returns a hash function implementing
     * <a href="https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp">MurmurHash3
     * algorithm</a> without seed values. This implementation produces equal results for equal input
     * on platforms with different {@link ByteOrder}, but is slower on big-endian platforms than on
     * little-endian.
     *
     * @see #murmur_3(long)
     */
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
    public static LongTupleHashFunction murmur_3(long seed) {
        return MurmurHash_3.asLongTupleHashFunctionWithSeed(seed);
    }

    public abstract long hashLong(long input, long[] result);
    public long hashLong(final long input) {
        return hashLong(input, null);
    }
    public long[] hashTupleLong(final long input) {
        final long[] result = newLongTuple();
        hashLong(input, result);
	return result;
    }

    public abstract long hashInt(int input, long[] result);
    public long hashInt(final int input) {
        return hashInt(input, null);
    }
    public long[] hashTupleInt(final int input) {
        final long[] result = newLongTuple();
        hashInt(input, result);
	return result;
    }

    public abstract long hashShort(short input, long[] result);
    public long hashShort(final short input) {
        return hashShort(input, null);
    }
    public long[] hashTupleShort(final short input) {
        final long[] result = newLongTuple();
        hashShort(input, result);
	return result;
    }

    public abstract long hashChar(char input, long[] result);
    public long hashChar(final char input) {
        return hashChar(input, null);
    }
    public long[] hashTupleChar(final char input) {
        final long[] result = newLongTuple();
        hashChar(input, result);
	return result;
    }

    public abstract long hashByte(byte input, long[] result);
    public long hashByte(final byte input) {
        return hashByte(input, null);
    }
    public long[] hashTupleByte(final byte input) {
        final long[] result = newLongTuple();
        hashByte(input, result);
	return result;
    }

    public abstract long[] hashTupleVoid();
    public long hashVoid() {
        return hashTupleVoid()[0];
    }

    public abstract <T> long hash(T input, Access<T> access, long off, long len, long[] result);
    public <T> long hash(final T input, final Access<T> access, final long off, final long len) {
        return hash(input, access, off, len, null);
    }
    public <T> long[] hashTuple(final T input, final Access<T> access, final long off, final long len) {
        final long[] result = newLongTuple();
        hash(input, access, off, len, result);
	return result;
    }

    private long unsafeHash(final Object input, final long off, final long len) {
        return hash(input, UnsafeAccess.INSTANCE, off, len, null);
    }
    private long unsafeHash(final Object input, final long off, final long len, long[] result) {
        return hash(input, UnsafeAccess.INSTANCE, off, len, result);
    }
    private long[] unsafeHashTuple(final Object input, final long off, final long len) {
        final long[] result = newLongTuple();
        hash(input, UnsafeAccess.INSTANCE, off, len, result);
	return result;
    }

    public long hashBoolean(final boolean input, final long[] result) {
        return hashByte(input ? TRUE_BYTE_VALUE : FALSE_BYTE_VALUE, result);
    }
    public long hashBoolean(final boolean input) {
        return hashByte(input ? TRUE_BYTE_VALUE : FALSE_BYTE_VALUE, null);
    }
    public long[] hashTupleBoolean(final boolean input) {
        final long[] result = newLongTuple();
        hashByte(input ? TRUE_BYTE_VALUE : FALSE_BYTE_VALUE, result);
	return result;
    }

    public long hashBooleans(@NotNull final boolean[] input, final long[] result) {
        return unsafeHash(input, BOOLEAN_BASE, input.length, result);
    }
    public long hashBooleans(@NotNull final boolean[] input) {
        return unsafeHash(input, BOOLEAN_BASE, input.length, null);
    }
    public long[] hashTupleBooleans(@NotNull final boolean[] input) {
        final long[] result = newLongTuple();
        unsafeHash(input, BOOLEAN_BASE, input.length, result);
	return result;
    }

    public long hashBooleans(@NotNull final boolean[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, BOOLEAN_BASE + off, len, result);
    }
    public long hashBooleans(@NotNull final boolean[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, BOOLEAN_BASE + off, len, null);
    }
    public long[] hashTupleBooleans(@NotNull final boolean[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newLongTuple();
        unsafeHash(input, BOOLEAN_BASE + off, len, result);
	return result;
    }

    public long hashBytes(@NotNull final byte[] input, final long[] result) {
        return unsafeHash(input, BYTE_BASE, input.length, result);
    }
    public long hashBytes(@NotNull final byte[] input) {
        return unsafeHash(input, BYTE_BASE, input.length, null);
    }
    public long[] hashTupleBytes(@NotNull final byte[] input) {
        final long[] result = newLongTuple();
        unsafeHash(input, BYTE_BASE, input.length, result);
	return result;
    }

    public long hashBytes(@NotNull final byte[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, BYTE_BASE + off, len, result);
    }
    public long hashBytes(@NotNull final byte[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, BYTE_BASE + off, len, null);
    }
    public long[] hashTupleBytes(@NotNull final byte[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newLongTuple();
        unsafeHash(input, BYTE_BASE + off, len, result);
	return result;
    }

    public long hashBytes(final ByteBuffer input, final long[] result) {
        return hashByteBuffer(input, input.position(), input.remaining(), result);
    }
    public long hashBytes(final ByteBuffer input) {
        return hashByteBuffer(input, input.position(), input.remaining(), null);
    }
    public long[] hashTupleBytes(final ByteBuffer input) {
        final long[] result = newLongTuple();
        hashByteBuffer(input, input.position(), input.remaining(), result);
	return result;
    }

    public long hashBytes(@NotNull final ByteBuffer input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.capacity(), off, len);
        return hashByteBuffer(input, off, len, result);
    }
    public long hashBytes(@NotNull final ByteBuffer input, final int off, final int len) {
        checkArrayOffs(input.capacity(), off, len);
        return hashByteBuffer(input, off, len, null);
    }
    public long[] hashTupleBytes(@NotNull final ByteBuffer input, final int off, final int len) {
        checkArrayOffs(input.capacity(), off, len);
        final long[] result = newLongTuple();
        hashByteBuffer(input, off, len, result);
	return result;
    }

    private long hashByteBuffer(@NotNull final ByteBuffer input, final int off, final int len, final long[] result) {
        if (input.hasArray()) {
            return unsafeHash(input.array(), BYTE_BASE + input.arrayOffset() + off, len, result);
        } else if (input instanceof DirectBuffer) {
            return unsafeHash(null, ((DirectBuffer) input).address() + off, len, result);
        } else {
            return hash(input, ByteBufferAccess.INSTANCE, off, len, result);
        }
    }

    public long hashMemory(final long address, final long len, final long[] result) {
        return unsafeHash(null, address, len, result);
    }
    public long hashMemory(final long address, final long len) {
        return unsafeHash(null, address, len, null);
    }
    public long[] hashTupleMemory(final long address, final long len) {
        final long[] result = newLongTuple();
        unsafeHash(null, address, len, result);
	return result;
    }

    public long hashChars(@NotNull final char[] input, final long[] result) {
        return unsafeHash(input, CHAR_BASE, input.length * 2L, result);
    }
    public long hashChars(@NotNull final char[] input) {
        return unsafeHash(input, CHAR_BASE, input.length * 2L, null);
    }
    public long[] hashTupleChars(@NotNull final char[] input) {
        final long[] result = newLongTuple();
        unsafeHash(input, CHAR_BASE, input.length * 2L, result);
	return result;
    }

    public long hashChars(@NotNull final char[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, CHAR_BASE + (off * 2L), len * 2L, result);
    }
    public long hashChars(@NotNull final char[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, CHAR_BASE + (off * 2L), len * 2L, null);
    }
    public long[] hashTupleChars(@NotNull final char[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newLongTuple();
        unsafeHash(input, CHAR_BASE + (off * 2L), len * 2L, result);
	return result;
    }

    public long hashChars(@NotNull final String input, final long[] result) {
        return stringHash.longHash(input, this, 0, input.length(), result);
    }
    public long hashChars(@NotNull final String input) {
        return stringHash.longHash(input, this, 0, input.length(), null);
    }
    public long[] hashTupleChars(@NotNull final String input) {
        final long[] result = newLongTuple();
        stringHash.longHash(input, this, 0, input.length(), result);
	return result;
    }

    public long hashChars(@NotNull final String input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length(), off, len);
        return stringHash.longHash(input, this, off, len, result);
    }
    public long hashChars(@NotNull final String input, final int off, final int len) {
        checkArrayOffs(input.length(), off, len);
        return stringHash.longHash(input, this, off, len, null);
    }
    public long[] hashTupleChars(@NotNull final String input, final int off, final int len) {
        checkArrayOffs(input.length(), off, len);
        final long[] result = newLongTuple();
        stringHash.longHash(input, this, off, len, result);
	return result;
    }

    public long hashChars(@NotNull final StringBuilder input, final long[] result) {
        return hashNativeChars(input, result);
    }
    public long hashChars(@NotNull final StringBuilder input) {
        return hashNativeChars(input, null);
    }
    public long[] hashTupleChars(@NotNull final StringBuilder input) {
        final long[] result = newLongTuple();
        hashNativeChars(input, result);
        return result;
    }

    public long hashChars(@NotNull final StringBuilder input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length(), off, len);
        return hashNativeChars(input, off, len, result);
    }
    public long hashChars(@NotNull final StringBuilder input, final int off, final int len) {
        checkArrayOffs(input.length(), off, len);
        return hashNativeChars(input, off, len, null);
    }
    public long[] hashTupleChars(@NotNull final StringBuilder input, final int off, final int len) {
        checkArrayOffs(input.length(), off, len);
        final long[] result = newLongTuple();
        hashNativeChars(input, off, len, result);
	return result;
    }

    long hashNativeChars(final CharSequence input, final long[] result) {
        return hashNativeChars(input, 0, input.length(), result);
    }

    long hashNativeChars(final CharSequence input, final int off, final int len, final long[] result) {
        return hash(input, nativeCharSequenceAccess(), off * 2L, len * 2L, result);
    }

    public long hashShorts(@NotNull final short[] input, final long[] result) {
        return unsafeHash(input, SHORT_BASE, input.length * 2L, result);
    }
    public long hashShorts(@NotNull final short[] input) {
        return unsafeHash(input, SHORT_BASE, input.length * 2L, null);
    }
    public long[] hashTupleShorts(@NotNull final short[] input) {
        final long[] result = newLongTuple();
        unsafeHash(input, SHORT_BASE, input.length * 2L, result);
	return result;
    }

    public long hashShorts(@NotNull final short[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, SHORT_BASE + (off * 2L), len * 2L, result);
    }
    public long hashShorts(@NotNull final short[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, SHORT_BASE + (off * 2L), len * 2L, null);
    }
    public long[] hashTupleShorts(@NotNull final short[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newLongTuple();
        unsafeHash(input, SHORT_BASE + (off * 2L), len * 2L, result);
	return result;
    }

    public long hashInts(@NotNull final int[] input, final long[] result) {
        return unsafeHash(input, INT_BASE, input.length * 4L, result);
    }
    public long hashInts(@NotNull final int[] input) {
        return unsafeHash(input, INT_BASE, input.length * 4L, null);
    }
    public long[] hashTupleInts(@NotNull final int[] input) {
        final long[] result = newLongTuple();
        unsafeHash(input, INT_BASE, input.length * 4L, result);
        return result;
    }

    public long hashInts(@NotNull final int[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, INT_BASE + (off * 4L), len * 4L, result);
    }
    public long hashInts(@NotNull final int[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, INT_BASE + (off * 4L), len * 4L, null);
    }
    public long[] hashTupleInts(@NotNull final int[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newLongTuple();
        unsafeHash(input, INT_BASE + (off * 4L), len * 4L, result);
	return result;
    }

    public long hashLongs(@NotNull final long[] input, final long[] result) {
        return unsafeHash(input, LONG_BASE, input.length * 8L, result);
    }
    public long hashLongs(@NotNull final long[] input) {
        return unsafeHash(input, LONG_BASE, input.length * 8L, null);
    }
    public long[] hashTupleLongs(@NotNull final long[] input) {
        final long[] result = newLongTuple();
        unsafeHash(input, LONG_BASE, input.length * 8L, result);
	return result;
    }

    public long hashLongs(@NotNull final long[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, LONG_BASE + (off * 8L), len * 8L, result);
    }
    public long hashLongs(@NotNull final long[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        return unsafeHash(input, LONG_BASE + (off * 8L), len * 8L, null);
    }
    public long[] hashTupleLongs(@NotNull final long[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newLongTuple();
        unsafeHash(input, LONG_BASE + (off * 8L), len * 8L, result);
	return result;
    }
}

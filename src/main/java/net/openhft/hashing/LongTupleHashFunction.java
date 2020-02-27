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

/**
 * Tuple hash function producing {@code long[]} result from byte sequences of any length and
 * a plenty of different sources which "feels like byte sequences". Except {@link
 * #hashBytes(byte[])}, {@link #hashBytes(ByteBuffer)} (with their "sliced" versions) and
 * {@link #hashMemory(long, long)} methods, which actually accept byte sequences, notion of byte
 * sequence is defined as follows:
 * <ul>
 *     <li>For methods accepting arrays of Java primitives, {@code String}s and
 *     {@code StringBuilder}s, byte sequence is how the input's bytes are actually lay in memory.
 *     </li>
 *     <li>For methods accepting single primitive values, byte sequence is how this primitive
 *     would be put into memory with {@link ByteOrder#nativeOrder() native} byte order, or
 *     equivalently, {@code hashXxx(primitive)} has always the same result as {@code
 *     hashXxxs(new xxx[] {primitive})}, where "xxx" is any Java primitive type name.</li>
 *     <li>For {@link #hash(Object, Access, long, long)} method byte sequence abstraction
 *     is defined by the given {@link Access} strategy to the given object.</li>
 * </ul>
 *
 * <p>Tuple hash function implementation could either produce equal results for equal input on platforms
 * with different {@link ByteOrder}, favoring one byte order in terms of performance, or different
 * results, but performing equally good. This choice should be explicitly documented for all
 * {@code LongTupleHashFunction} implementations.
 *
 * Each hash api have two forms:
 * <ul>
 *     <li> {code void hash(input..., long[] result)} will put the hash result in array {@code result}
 *     <li> {code long[] hash(input...)} will alloc and return an array container the results
 * </ul>
 * ${@code newResultArray()} api should always be used to create resuable result arrays. And a hash
 * implementation can omit checking the length of result arrays for better performance.
 *
 * <h3>Subclassing</h3>
 * To implement a specific hash function algorithm resulting more than 64 bits results,
 * this class should be subclassed. Only methods with resued result array that accept single primitives,
 * {@link #hashVoid(long[])} and {@link #hash(Object, Access, long, long, long[])} should be implemented;
 * other have default implementations which in the end delegate to
 * {@link #hash(Object, Access, long, long, long[])} abstract method.
 *
 * The {@code #bitsLength()} method should also be implemented, returning the actual bits in the result
 * array. The bits length should be greater than 64, otherwise just using the {@link #LongHashFunction}
 * interface. And the length should also be a positive multiple of 8.
 *
 * <p>Notes about how exactly methods with default implementations are implemented in doc comments
 * are given for information and could be changed at any moment. However, it could hardly cause
 * any issues with subclassing, except probably little performance degradation. Methods documented
 * as "shortcuts" could either delegate to the referenced method or delegate directly to the method
 * to which the referenced method delegates.
 *
 *<p>{@code LongTupleHashFunction} implementations shouldn't assume that {@code Access} strategies
 * do defensive checks, and access only bytes within the requested range.
 */
@ParametersAreNonnullByDefault
public abstract class LongTupleHashFunction implements Serializable {
    private static final long serialVersionUID = 0L;

    // Implementations
    //

    /**
     * Returns a 128-bit hash function implementing
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
     * Returns a 128-bit hash function implementing
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

    /**
     * Constructor for use in subclasses.
     */
    protected LongTupleHashFunction() {}

    // Public API
    //

    /**
     * Returns the number of bits in a result array; a positive multiple of 8.
     */
    public abstract int bitsLength();

    /**
     * Returns a result array
     */
    @NotNull
    public long[] newResultArray() {
        return new long[(bitsLength() + 63) / 64];
    }

    /**
     * Returns the hash code for the given {@code long} value; this method is consistent with
     * {@code LongTupleHashFunction} methods that accept sequences of bytes, assuming the {@code input}
     * value is interpreted in {@linkplain ByteOrder#nativeOrder() native} byte order. For example,
     * the result of {@code hashLong(v, result)} call is identical to the result of
     * {@code hashLongs(new long[] {v}, result)} call for any {@code long} value.
     */
    public abstract void hashLong(long input, long[] result);

    /**
     * See {@link #hashLong(long, long[])}
     */
    @NotNull
    public long[] hashLong(final long input) {
        final long[] result = newResultArray();
        hashLong(input, result);
        return result;
    }

    /**
     * Returns the hash code for the given {@code int} value; this method is consistent with
     * {@code LongTupleHashFunction} methods that accept sequences of bytes, assuming the {@code input}
     * value is interpreted in {@linkplain ByteOrder#nativeOrder() native} byte order. For example,
     * the result of {@code hashInt(v, result)} call is identical to the result of
     * {@code hashInts(new int[] {v}, result)} call for any {@code int} value.
     */
    public abstract void hashInt(int input, long[] result);

    /**
     * See {@link #hashInt(int, long[])}
     */
    @NotNull
    public long[] hashInt(final int input) {
        final long[] result = newResultArray();
        hashInt(input, result);
        return result;
    }

    /**
     * Returns the hash code for the given {@code short} value; this method is consistent with
     * {@code LongTupleHashFunction} methods that accept sequences of bytes, assuming the {@code input}
     * value is interpreted in {@linkplain ByteOrder#nativeOrder() native} byte order. For example,
     * the result of {@code hashShort(v, result)} call is identical to the result of
     * {@code hashShorts(new short[] {v}, result)} call for any {@code short} value.
     * As a consequence, {@code hashShort(v, result)} call produce always the same result as {@code
     * hashChar((char) v, result)}.
     */
    public abstract void hashShort(short input, long[] result);

    /**
     * See {@link #hashShort(short, long[])}
     */
    @NotNull
    public long[] hashShort(final short input) {
        final long[] result = newResultArray();
        hashShort(input, result);
        return result;
    }

    /**
     * Returns the hash code for the given {@code char} value; this method is consistent with
     * {@code LongTupleHashFunction} methods that accept sequences of bytes, assuming the {@code input}
     * value is interpreted in {@linkplain ByteOrder#nativeOrder() native} byte order. For example,
     * the result of {@code hashChar(v, result)} call is identical to the result of
     * {@code hashChars(new char[] {v}, result)} call for any {@code char} value.
     * As a consequence, {@code hashChar(v, result)} call produce always the same result as {@code
     * hashShort((short) v, result)}.
     */
    public abstract void hashChar(char input, long[] result);

    /**
     * See {@link #hashChar(char, long[])}
     */
    @NotNull
    public long[] hashChar(final char input) {
        final long[] result = newResultArray();
        hashChar(input, result);
        return result;
    }

    /**
     * Returns the hash code for the given {@code byte} value. This method is consistent with
     * {@code LongTupleHashFunction} methods that accept sequences of bytes. For example, the result of
     * {@code hashByte(v, result)} call is identical to the result of
     * {@code hashBytes(new byte[] {v}, result)} call for any {@code byte} value.
     */
    public abstract void hashByte(byte input, long[] result);

    /**
     * See {@link #hashByte(byte, long[])}
     */
    @NotNull
    public long[] hashByte(final byte input) {
        final long[] result = newResultArray();
        hashByte(input, result);
        return result;
    }

    /**
     * Returns the hash code for the empty (zero-length) bytes sequence,
     * for example {@code hashBytes(new byte[0], result)}.
     */
    public abstract void hashVoid(long[] result);

    /**
     * See {@link #hashVoid(long[])}
     */
    @NotNull
    public long[] hashVoid() {
        final long[] result = newResultArray();
        hashVoid(result);
        return result;
    }

    /**
     * Returns the hash code for {@code len} continuous bytes of the given {@code input} object,
     * starting from the given offset. The abstraction of input as ordered byte sequence and
     * "offset within the input" is defined by the given {@code access} strategy.
     *
     * <p>This method doesn't promise to throw a {@code RuntimeException} if {@code
     * [off, off + len - 1]} subsequence exceeds the bounds of the bytes sequence, defined by {@code
     * access} strategy for the given {@code input}, so use this method with caution.
     *
     * @param input the object to read bytes from
     * @param access access which defines the abstraction of the given input
     *               as ordered byte sequence
     * @param off offset to the first byte of the subsequence to hash
     * @param len length of the subsequence to hash
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @param <T> the type of the input
     */
    public abstract <T> void hash(@Nullable T input, Access<T> access, long off, long len, long[] result);

    /**
     * See {@link #hash(T, Access, long, long, long[])}
     */
    @NotNull
    public <T> long[] hash(@Nullable final T input, final Access<T> access, final long off, final long len) {
        final long[] result = newResultArray();
        hash(input, access, off, len, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashBooleans(boolean[], long[]) hashBooleans(new boolean[] &#123;input&#125;, result)}.
     * Note that this is not necessarily equal to {@code hashByte(input ? (byte) 1 : (byte) 0, result)},
     * because booleans could be stored differently in this JVM.
     */
    public void hashBoolean(final boolean input, final long[] result) {
        hashByte(input ? TRUE_BYTE_VALUE : FALSE_BYTE_VALUE, result);
    }

    /**
     * See {@link #hashBoolean(boolean, long[])}
     */
    @NotNull
    public long[] hashBoolean(final boolean input) {
        final long[] result = newResultArray();
        hashByte(input ? TRUE_BYTE_VALUE : FALSE_BYTE_VALUE, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashBooleans(boolean[], int, int, long[]) hashBooleans(input, 0, input.length, result)}.
     */
    public void hashBooleans(final boolean[] input, final long[] result) {
        unsafeHash(this, input, BOOLEAN_BASE, input.length, result);
    }

    /**
     * See {@link #hashBooleans(boolean[], long[])}
     */
    @NotNull
    public long[] hashBooleans(final boolean[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, BOOLEAN_BASE, input.length, result);
        return result;
    }

    /**
     * Returns the hash code for the specified subsequence of the given {@code boolean} array.
     *
     * <p>Default implementation delegates to {@link #hash(Object, Access, long, long, long[])} method
     * using {@linkplain Access#unsafe() unsafe} {@code Access}.
     *
     * @param input the array to read data from
     * @param off index of the first {@code boolean} in the subsequence to hash
     * @param len length of the subsequence to hash
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashBooleans(final boolean[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, BOOLEAN_BASE + off, len, result);
    }

    /**
     * See {@link #hashBooleans(boolean[], int, int, long[])}
     */
    @NotNull
    public long[] hashBooleans(final boolean[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, BOOLEAN_BASE + off, len, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashBytes(byte[], int, int, long[]) hashBytes(input, 0, input.length, result)}.
     */
    public void hashBytes(final byte[] input, final long[] result) {
        unsafeHash(this, input, BYTE_BASE, input.length, result);
    }

    /**
     * See {@link #hashBytes(byte[], long[])}
     */
    @NotNull
    public long[] hashBytes(final byte[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, BYTE_BASE, input.length, result);
        return result;
    }

    /**
     * Returns the hash code for the specified subsequence of the given {@code byte} array.
     *
     * <p>Default implementation delegates to {@link #hash(Object, Access, long, long, long[])}
     * method using {@linkplain Access#unsafe() unsafe} {@code Access}.
     *
     * @param input the array to read bytes from
     * @param off index of the first {@code byte} in the subsequence to hash
     * @param len length of the subsequence to hash
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashBytes(final byte[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, BYTE_BASE + off, len, result);
    }

    /**
     * See {@link #hashBytes(byte[], int, int, long[])}
     */
    @NotNull
    public long[] hashBytes(final byte[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, BYTE_BASE + off, len, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashBytes(ByteBuffer, int, int, long[])
     * hashBytes(input, input.position(), input.remaining(), result)}.
     */
    public void hashBytes(final ByteBuffer input, final long[] result) {
        hashByteBuffer(this, input, input.position(), input.remaining(), result);
    }

    /**
     * See {@link #hashBytes(ByteBuffer, long[])}
     */
    @NotNull
    public long[] hashBytes(final ByteBuffer input) {
        final long[] result = newResultArray();
        hashByteBuffer(this, input, input.position(), input.remaining(), result);
        return result;
    }

    /**
     * Returns the hash code for the specified subsequence of the given {@code ByteBuffer}.
     *
     * <p>This method doesn't alter the state (mark, position, limit or order) of the given
     * {@code ByteBuffer}.
     *
     * <p>Default implementation delegates to {@link #hash(Object, Access, long, long, long[])}
     * method using {@link Access#toByteBuffer()}.
     *
     * @param input the buffer to read bytes from
     * @param off index of the first {@code byte} in the subsequence to hash
     * @param len length of the subsequence to hash
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.capacity()}
     * or {@code len < 0}
     */
    public void hashBytes(final ByteBuffer input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.capacity(), off, len);
        hashByteBuffer(this, input, off, len, result);
    }

    /**
     * See {@link #hashBytes(ByteBuffer, int, int, long[])}
     */
    @NotNull
    public long[] hashBytes(final ByteBuffer input, final int off, final int len) {
        checkArrayOffs(input.capacity(), off, len);
        final long[] result = newResultArray();
        hashByteBuffer(this, input, off, len, result);
        return result;
    }

    /**
     * Returns the hash code of bytes of the wild memory from the given address. Use with caution.
     *
     * <p>Default implementation delegates to {@link #hash(Object, Access, long, long, long[])}
     * method using {@linkplain Access#unsafe() unsafe} {@code Access}.
     *
     * @param address the address of the first byte to hash
     * @param len length of the byte sequence to hash
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     */
    public void hashMemory(final long address, final long len, final long[] result) {
        unsafeHash(this, null, address, len, result);
    }

    /**
     * See {@link #hashMemory(long, long, long[])}
     */
    @NotNull
    public long[] hashMemory(final long address, final long len) {
        final long[] result = newResultArray();
        unsafeHash(this, null, address, len, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashChars(char[], int, int, long[]) hashChars(input, 0, input.length, result)}.
     */
    public void hashChars(final char[] input, final long[] result) {
        unsafeHash(this, input, CHAR_BASE, input.length * 2L, result);
    }

    /**
     * See {@link #hashChars(char[], long[])}
     */
    @NotNull
    public long[] hashChars(final char[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, CHAR_BASE, input.length * 2L, result);
        return result;
    }

    /**
     * Returns the hash code for bytes, as they lay in memory, of the specified subsequence
     * of the given {@code char} array.
     *
     * <p>Default implementation delegates to {@link #hash(Object, Access, long, long, long[])}
     * method using {@linkplain Access#unsafe() unsafe} {@code Access}.
     *
     * @param input the array to read data from
     * @param off index of the first {@code char} in the subsequence to hash
     * @param len length of the subsequence to hash, in chars (i. e. the length of the bytes
     *            sequence to hash is {@code len * 2L})
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashChars(final char[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, CHAR_BASE + (off * 2L), len * 2L, result);
    }

    /**
     * See {@link #hashChars(char[], int, int, long[])}
     */
    @NotNull
    public long[] hashChars(final char[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, CHAR_BASE + (off * 2L), len * 2L, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashChars(String, int, int, long[]) hashChars(input, 0, input.length(), result)}.
     */
    public void hashChars(final String input, final long[] result) {
        VALID_STRING_HASH.hash(input, this, 0, input.length(), result);
    }

    /**
     * See {@link #hashChars(String, long[])}
     */
    @NotNull
    public long[] hashChars(final String input) {
        final long[] result = newResultArray();
        VALID_STRING_HASH.hash(input, this, 0, input.length(), result);
        return result;
    }

    /**
     * Returns the hash code for bytes of the specified subsequence of the given {@code String}'s
     * underlying {@code char} array.
     *
     * <p>Default implementation could either delegate to {@link #hash(Object, Access, long, long, long[])}
     * using {@link Access#toNativeCharSequence()}, or to {@link #hashChars(char[], int, int, long[])}.
     *
     * @param input the string which bytes to hash
     * @param off index of the first {@code char} in the subsequence to hash
     * @param len length of the subsequence to hash, in chars (i. e. the length of the bytes
     *            sequence to hash is {@code len * 2L})
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.length()}
     * or {@code len < 0}
     */
    public void hashChars(final String input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length(), off, len);
        VALID_STRING_HASH.hash(input, this, off, len, result);
    }

    /**
     * See {@link #hashChars(String, int, int long[])}
     */
    @NotNull
    public long[] hashChars(final String input, final int off, final int len) {
        checkArrayOffs(input.length(), off, len);
        final long[] result = newResultArray();
        VALID_STRING_HASH.hash(input, this, off, len, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashChars(T, int, int, result) hashChars(input, 0, input.length(), result)}.
     */
    public <T extends CharSequence> void hashChars(final T input, final long[] result) {
        hashNativeChars(this, input, 0, input.length(), result);
    }

    /**
     * See {@link #hashChars(T, long[])}
     */
    @NotNull
    public <T extends CharSequence> long[] hashChars(final T input) {
        final long[] result = newResultArray();
        hashNativeChars(this, input, 0, input.length(), result);
        return result;
    }

    /**
     * Returns the hash code for bytes of the specified subsequence of the given
     * {@code CharSequence}'s underlying {@code char} array.
     *
     * <p>Default implementation could either delegate to {@link #hash(Object, Access, long, long, result)}
     * using {@link Access#toNativeCharSequence()}.
     *
     * @param input the char sequence which bytes to hash
     * @param off index of the first {@code char} in the subsequence to hash
     * @param len length of the subsequence to hash, in chars (i. e. the length of the bytes
     *            sequence to hash is {@code len * 2L})
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @param <T> the type of the input which extends CharSequence
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.length()}
     * or {@code len < 0}
     */
    public <T extends CharSequence> void hashChars(final T input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length(), off, len);
        hashNativeChars(this, input, off, len, result);
    }

    /**
     * See {@link #hashChars(T, int, int, long[])}
     */
    @NotNull
    public <T extends CharSequence> long[] hashChars(final T input, final int off, final int len) {
        checkArrayOffs(input.length(), off, len);
        final long[] result = newResultArray();
        hashNativeChars(this, input, off, len, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashShorts(short[], int, int, long[]) hashShorts(input, 0, input.length, result)}.
     */
    public void hashShorts(final short[] input, final long[] result) {
        unsafeHash(this, input, SHORT_BASE, input.length * 2L, result);
    }

    /**
     * See {@link #hashShorts(short[], long[])}
     */
    @NotNull
    public long[] hashShorts(final short[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, SHORT_BASE, input.length * 2L, result);
        return result;
    }

    /**
     * Returns the hash code for bytes, as they lay in memory, of the specified subsequence
     * of the given {@code short} array.
     *
     * <p>Default implementation delegates to {@link #hash(Object, Access, long, long, long[])}
     * method using {@linkplain Access#unsafe() unsafe} {@code Access}.
     *
     * @param input the array to read data from
     * @param off index of the first {@code short} in the subsequence to hash
     * @param len length of the subsequence to hash, in shorts (i. e. the length of the bytes
     *            sequence to hash is {@code len * 2L})
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashShorts(final short[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, SHORT_BASE + (off * 2L), len * 2L, result);
    }

    /**
     * See {@link #hashShorts(short[], int, int, long[])}
     */
    @NotNull
    public long[] hashShorts(final short[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, SHORT_BASE + (off * 2L), len * 2L, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashInts(int[], int, int, long[]) hashInts(input, 0, input.length, result)}.
     */
    public void hashInts(final int[] input, final long[] result) {
        unsafeHash(this, input, INT_BASE, input.length * 4L, result);
    }

    /**
     * See {@link #hashInts(int[], long[])}
     */
    @NotNull
    public long[] hashInts(final int[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, INT_BASE, input.length * 4L, result);
        return result;
    }

    /**
     * Returns the hash code for bytes, as they lay in memory, of the specified subsequence
     * of the given {@code int} array.
     *
     * <p>Default implementation delegates to {@link #hash(Object, Access, long, long, long[])}
     * method using {@linkplain Access#unsafe() unsafe} {@code Access}.
     *
     * @param input the array to read data from
     * @param off index of the first {@code int} in the subsequence to hash
     * @param len length of the subsequence to hash, in ints (i. e. the length of the bytes
     *            sequence to hash is {@code len * 4L})
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashInts(final int[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, INT_BASE + (off * 4L), len * 4L, result);
    }

    /**
     * See {@link #hashInts(int[], int, int, long[])}
     */
    @NotNull
    public long[] hashInts(final int[] input, final int off, final int len) {
        checkArrayOffs(input.length, off, len);
        final long[] result = newResultArray();
        unsafeHash(this, input, INT_BASE + (off * 4L), len * 4L, result);
        return result;
    }

    /**
     * Shortcut for {@link #hashLongs(long[], int, int, long[]) hashLongs(input, 0, input.length, result)}.
     */
    public void hashLongs(final long[] input, final long[] result) {
        unsafeHash(this, input, LONG_BASE, input.length * 8L, result);
    }

    /**
     * See {@link #hashLongs(long[], long[])}
     */
    @NotNull
    public long[] hashLongs(final long[] input) {
        final long[] result = newResultArray();
        unsafeHash(this, input, LONG_BASE, input.length * 8L, result);
        return result;
    }

    /**
     * Returns the hash code for bytes, as they lay in memory, of the specified subsequence
     * of the given {@code long} array.
     *
     * <p>Default implementation delegates to {@link #hash(Object, Access, long, long, long[])}
     * method using {@linkplain Access#unsafe() unsafe} {@code Access}.
     *
     * @param input the array to read data from
     * @param off index of the first {@code long} in the subsequence to hash
     * @param len length of the subsequence to hash, in longs (i. e. the length of the bytes
     *            sequence to hash is {@code len * 8L})
     * @param result the container array for putting the hash results,
     *               should be alloced by ${@code #newResultArray()}
     * @throws IndexOutOfBoundsException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashLongs(final long[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, LONG_BASE + (off * 8L), len * 8L, result);
    }

    /**
     * See {@link #hashLongs(long[], int, int, long[])}
     */
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

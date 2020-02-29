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
 * Tuple hash function producing more than 64-bit hash code into a result array of type
 * {@code long[]} from any byte sequences. See {@link LongHashFunction} for the definition of byte
 * sequence semantics and {@link ByteOrder} requirements for implementations.
 *
 * Every {#link LongHashFunction} hash method has two corresponding ones in this class for different
 * allocation stradges:
 * <ul>
 *     <li>{@code void hash(input..., long[] result)} will store the hash results in array
 *     {@code result[0 .. newResultArray().length-1]}, and throws exceptions when {@code result}
 *     is not valid. {@link #newResultArray} method should always be used to create resuable result
 *     arrays to avoid exceptions. See {@link #hash(long, long[])}.</li>
 *     <li>{@code long[] hash(input...)} will allocate and return an array containing the results.
 *     </li>
 * </ul>
 *
 * <b>Warning:</b> Allocations <strong>cannot</strong> be totally avoid to exchange a more than
 * 64-bit result since there is no value type in java yet. For the first form of a hash method, a
 * single allocation occurs only at the begining of some runtime scope, so it could be called
 * <strong>Almost-Zero-Allocation-Hashing</strong>.
 *
 * <b>Warning:</b> The second form <strong>always performs exactly one allocation</strong> for the
 * result array in each invocation, that is <strong>One-Allocation-Hashing</strong>. So prefer the
 * first form as much as possible.
 *
 * <h3>Subclassing</h3>
 * To implement a specific hash function algorithm resulting more than 64 bits results, this class
 * should be subclassed. Only methods with resued result array that accept single primitives,
 * {@link #hashVoid(long[])} and {@link #hash(Object, Access, long, long, long[])} should be
 * implemented; other have default implementations which in the end delegate to
 * {@link #hash(Object, Access, long, long, long[])} abstract method.
 *
 * The {@link #bitsLength} method should also be implemented, returning the actual number of bits in
 * the result array. The bits length should be greater than 64, otherwise just use the
 * {@link LongHashFunction} interface. And the length should also be a positive multiple of 8.
 *
 * @see LongHashFunction
 * for additional information about subclassing andd access.
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
     * Returns the actual number of bits in a result array; a positive multiple of 8.
     */
    public abstract int bitsLength();

    /**
     * Returns a new-allocated result array.
     */
    @NotNull
    public long[] newResultArray() {
        return new long[(bitsLength() + 63) / 64];
    }

    /**
     * Computes the hash code for the given {@code long} value, and store the results in the
     * {@code result} array; this method is consistent with {@code LongTupleHashFunction} methods
     * that accept sequences of bytes, assuming the {@code input} value is interpreted in
     * {@linkplain ByteOrder#nativeOrder() native} byte order. For example, the result of
     * {@code hashLong(v, result)} call is identical to the result of
     * {@code hashLongs(new long[] {v}, result)} call for any {@code long} value.
     *
     * The {@code result} array should be always created by {@link #newResultArray} method.
     * When storing, the {@code result[0 .. newResultArray().length-1]} will be accessed,
     * the rest elements of the array will not be touched when
     * {@code result.length > newResultArray().length]}.
     *
     * @throws NullPointerException if {@code result == null}
     * @throws IllegalArgumentException if {@code result.length < newResultArray().length}
     */
    public abstract void hashLong(long input, long[] result);

    /**
     * @see #hashLong(long, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
     */
    @NotNull
    public long[] hashLong(final long input) {
        final long[] result = newResultArray();
        hashLong(input, result);
        return result;
    }

    /**
     * Computes the hash code for the given {@code int} value, and store the results in the
     * {@code result} array; this method is consistent with {@code LongTupleHashFunction} methods
     * that accept sequences of bytes, assuming the {@code input} value is interpreted in
     * {@linkplain ByteOrder#nativeOrder() native} byte order. For example, the result of
     * {@code hashInt(v, result)} call is identical to the result of
     * {@code hashInts(new long[] {v}, result)} call for any {@code int} value.
     *
     * The {@code result} array should be always created by {@link #newResultArray} method.
     * When storing, the {@code result[0 .. newResultArray().length-1]} will be accessed,
     * the rest elements of the array will not be touched when
     * {@code result.length > newResultArray().length]}.
     *
     * @throws NullPointerException if {@code result == null}
     * @throws IllegalArgumentException if {@code result.length < newResultArray().length}
     */
    public abstract void hashInt(int input, long[] result);

    /**
     * @see #hashInt(int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
     */
    @NotNull
    public long[] hashInt(final int input) {
        final long[] result = newResultArray();
        hashInt(input, result);
        return result;
    }

    /**
     * Computes the hash code for the given {@code short} value, and store the results in the
     * {@code result} array; this method is consistent with {@code LongTupleHashFunction} methods
     * that accept sequences of bytes, assuming the {@code input} value is interpreted in
     * {@linkplain ByteOrder#nativeOrder() native} byte order. For example, the result of
     * {@code hashShort(v, result)} call is identical to the result of
     * {@code hashShorts(new long[] {v}, result)} call for any {@code short} value.
     *
     * The {@code result} array should be always created by {@link #newResultArray} method.
     * When storing, the {@code result[0 .. newResultArray().length-1]} will be accessed,
     * the rest elements of the array will not be touched when
     * {@code result.length > newResultArray().length]}.
     *
     * @throws NullPointerException if {@code result == null}
     * @throws IllegalArgumentException if {@code result.length < newResultArray().length}
     */
    public abstract void hashShort(short input, long[] result);

    /**
     * @see #hashShort(short, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
     */
    @NotNull
    public long[] hashShort(final short input) {
        final long[] result = newResultArray();
        hashShort(input, result);
        return result;
    }

    /**
     * TODO
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
     * @see #hashChar(char, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashByte(byte, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashVoid(long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @param <T> the type of the input
     */
    public abstract <T> void hash(@Nullable T input, Access<T> access,
                                  long off, long len, long[] result);

    /**
     * @see #hash(T, Access, long, long, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
     */
    @NotNull
    public <T> long[] hash(@Nullable final T input, final Access<T> access,
                           final long off, final long len) {
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
     * @see #hashBoolean(boolean, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashBooleans(boolean[], long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashBooleans(final boolean[] input,
                             final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, BOOLEAN_BASE + off, len, result);
    }

    /**
     * @see #hashBooleans(boolean[], int, int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashBytes(byte[], long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashBytes(final byte[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, BYTE_BASE + off, len, result);
    }

    /**
     * @see #hashBytes(byte[], int, int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashBytes(ByteBuffer, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.capacity()}
     * or {@code len < 0}
     */
    public void hashBytes(final ByteBuffer input,
                          final int off, final int len, final long[] result) {
        checkArrayOffs(input.capacity(), off, len);
        hashByteBuffer(this, input, off, len, result);
    }

    /**
     * @see #hashBytes(ByteBuffer, int, int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     */
    public void hashMemory(final long address, final long len, final long[] result) {
        unsafeHash(this, null, address, len, result);
    }

    /**
     * @see #hashMemory(long, long, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashChars(char[], long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashChars(final char[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, CHAR_BASE + (off * 2L), len * 2L, result);
    }

    /**
     * @see #hashChars(char[], int, int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashChars(String, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.length()}
     * or {@code len < 0}
     */
    public void hashChars(final String input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length(), off, len);
        VALID_STRING_HASH.hash(input, this, off, len, result);
    }

    /**
     * @see #hashChars(String, int, int long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashChars(T, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @param <T> the type of the input which extends CharSequence
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.length()}
     * or {@code len < 0}
     */
    public <T extends CharSequence> void hashChars(final T input, final int off, final int len,
                                                   final long[] result) {
        checkArrayOffs(input.length(), off, len);
        hashNativeChars(this, input, off, len, result);
    }

    /**
     * @see #hashChars(T, int, int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashShorts(short[], long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashShorts(final short[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, SHORT_BASE + (off * 2L), len * 2L, result);
    }

    /**
     * @see #hashShorts(short[], int, int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashInts(int[], long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashInts(final int[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, INT_BASE + (off * 4L), len * 4L, result);
    }

    /**
     * @see #hashInts(int[], int, int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     * @see #hashLongs(long[], long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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
     *               should be alloced by {@link #newResultArray}
     * @throws IllegalArgumentException if {@code off < 0} or {@code off + len > input.length}
     * or {@code len < 0}
     */
    public void hashLongs(final long[] input, final int off, final int len, final long[] result) {
        checkArrayOffs(input.length, off, len);
        unsafeHash(this, input, LONG_BASE + (off * 8L), len * 8L, result);
    }

    /**
     * @see #hashLongs(long[], int, int, long[])
     *
     * The result array will be allocated on the fly, and no exceptions will be thrown.
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

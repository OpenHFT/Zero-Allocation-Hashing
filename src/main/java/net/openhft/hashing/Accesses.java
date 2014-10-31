/*
 * Copyright 2014 Higher Frequency Trading http://www.higherfrequencytrading.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openhft.hashing;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Static methods returning useful {@link Access} implementations.
 */
public final class Accesses {

    /**
     * Returns the {@code Access} delegating {@code getXXX(input, offset)} methods to {@code
     * sun.misc.Unsafe.getXXX(input, offset)}.
     *
     * <p>Usage example: <pre>{@code
     * class Pair {
     *     long first, second;
     *
     *     static final long pairDataOffset =
     *         theUnsafe.objectFieldOffset(Pair.class.getDeclaredField("first"));
     *
     *     static long hashPair(Pair pair, LongHashFunction hashFunction) {
     *         return hashFunction.hash(pair, Accesses.unsafe(), pairDataOffset, 16L);
     *     }
     * }}</pre>
     *
     * <p>{@code null} is a valid input, on accepting {@code null} {@code Unsafe} just interprets
     * the given offset as a wild memory address. Note that for hashing memory by address there is
     * a shortcut {@link LongHashFunction#hashMemory(long, long) hashMemory(address, len)} method.
     *
     * @param <T> the type of objects to access
     * @return the unsafe memory {@code Access}
     */
    public static <T> Access<T> unsafe() {
        return (Access<T>) UnsafeAccess.INSTANCE;
    }

    /**
     * Returns the {@code Access} to any {@link ByteBuffer}. This {@code Access} isn't useful in
     * the user code, because methods {@link LongHashFunction#hashBytes(ByteBuffer)} and
     * {@link LongHashFunction#hashBytes(ByteBuffer, int, int)} exist. This {@code Access} could be
     * used in new {@link LongHashFunction} implementations.
     *
     * @return the {@code Access} to {@link ByteBuffer}s
     */
    public static Access<ByteBuffer> toByteBuffer() {
        return ByteBufferAccess.INSTANCE;
    }

    /**
     * Returns the {@code Access} to {@link CharSequence}s backed by {@linkplain
     * ByteOrder#nativeOrder() native} {@code char} reads, typically from {@code char[]} array.
     *
     * <p>Usage example:<pre>{@code
     * static long hashStringBuffer(StringBuffer buffer, LongHashFunction hashFunction) {
     *     return hashFunction.hash(buffer, Accesses.toNativeCharSequence(),
     *         // * 2L because length is passed in bytes, not chars
     *         0L, buffer.length() * 2L);
     * }}</pre>
     *
     * <p>This method is a shortcut for {@code Accesses.toCharSequence(ByteOrder.nativeOrder())}.
     *
     * @param <T> the {@code CharSequence} subtype (backed by native {@code char reads}) to access
     * @return the {@code Access} to {@link CharSequence}s backed by native {@code char} reads
     * @see #toCharSequence(ByteOrder)
     */
    public static <T extends CharSequence> Access<T> toNativeCharSequence() {
        return (Access<T>) CharSequenceAccess.nativeCharSequenceAccess();
    }

    /**
     * Returns the {@code Access} to {@link CharSequence}s backed by {@code char} reads made in
     * the specified byte order.
     *
     * <p>Usage example:<pre>{@code
     * static long hashCharBuffer(CharBuffer buffer, LongHashFunction hashFunction) {
     *     return hashFunction.hash(buffer, Accesses.toCharSequence(buffer.order()),
     *         // * 2L because length is passed in bytes, not chars
     *         0L, buffer.length() * 2L);
     * }}</pre>
     *
     * @param backingOrder the byte order of {@code char} reads backing
     * {@code CharSequences} to access
     * @return the {@code Access} to {@link CharSequence}s backed by {@code char} reads made in
     * the specified byte order
     * @param <T> the {@code CharSequence} subtype to access
     * @see #toNativeCharSequence()
     */
    public static <T extends CharSequence> Access<T> toCharSequence(ByteOrder backingOrder) {
        return (Access<T>) CharSequenceAccess.charSequenceAccess(backingOrder);
    }

    private Accesses() {}
}

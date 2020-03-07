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

import sun.nio.ch.DirectBuffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class LongHashFunctionTest {

    private static ByteOrder nonNativeOrder() {
        return nativeOrder() == LITTLE_ENDIAN ? BIG_ENDIAN : LITTLE_ENDIAN;
    }

    public static void test(LongHashFunction f, byte[] data, long eh) {
        int len = data.length;
        testVoid(f, eh, len);
        testBoolean(f, len);
        ByteBuffer bb = ByteBuffer.wrap(data).order(nativeOrder());
        testPrimitives(f, eh, len, bb);
        testNegativePrimitives(f);
        testArrays(f, data, eh, len, bb);
        testByteBuffers(f, eh, len, bb);
        testCharSequences(f, eh, len, bb);
        testMemory(f, eh, len, bb);
    }

    private static void testVoid(LongHashFunction f, long eh, int len) {
        if (len == 0)
            assertEquals("void", eh, f.hashVoid());
    }
    
    public static void testBoolean(LongHashFunction f, int len) {
        if (len != 1)
            return;
        for (boolean b : new boolean[] {true, false}) {
            boolean[] a = {b};
            long single = f.hashBoolean(b);
            long array = f.hashBooleans(a);
            assertEquals(single, array);
            assertEquals(single, f.hash(a, UnsafeAccess.unsafe(), UnsafeAccess.BOOLEAN_BASE, 1L));
        }
    }

    private static void testPrimitives(LongHashFunction f, long eh, int len, ByteBuffer bb) {
        long actual;
        if (len == 1) {
            actual = f.hashByte(bb.get(0));
            assertEquals("byte hash", eh, actual);
        }

        if (len == 2) {
            actual = f.hashShort(bb.getShort(0));
            assertEquals("short hash", eh, actual);
            actual = f.hashChar(bb.getChar(0));
            assertEquals("char hash", eh, actual);
        }

        if (len == 4) {
            actual = f.hashInt(bb.getInt(0));
            assertEquals("int hash", eh, actual);
        }
        if (len == 8) {
            actual = f.hashLong(bb.getLong(0));
            assertEquals("long hash", eh, actual);
        }
    }

    private static void testNegativePrimitives(LongHashFunction f) {
        byte[] bytes = new byte[8];
        Arrays.fill(bytes, (byte) -1);
        long oneByteExpected = f.hashBytes(bytes, 0, 1);
        long twoByteExpected = f.hashBytes(bytes, 0, 2);
        long fourByteExpected = f.hashBytes(bytes, 0, 4);
        long eightByteExpected = f.hashBytes(bytes);
        assertEquals("byte hash", oneByteExpected, f.hashByte((byte) -1));
        assertEquals("short hash", twoByteExpected, f.hashShort((short) -1));
        assertEquals("char hash", twoByteExpected, f.hashChar((char) -1));
        assertEquals("int hash", fourByteExpected, f.hashInt(-1));
        assertEquals("long hash", eightByteExpected, f.hashLong(-1L));
    }

    private static void testArrays(LongHashFunction f, byte[] data, long eh, int len,
                                   ByteBuffer bb) {
        assertEquals("byte array", eh, f.hashBytes(data));

        byte[] data2 = new byte[len + 2];
        System.arraycopy(data, 0, data2, 1, len);
        assertEquals("byte array off len", eh, f.hashBytes(data2, 1, len));

        if ((len & 1) == 0) {
            int shortLen = len / 2;

            short[] shorts = new short[shortLen];
            bb.asShortBuffer().get(shorts);
            assertEquals("short array", eh, f.hashShorts(shorts));

            short[] shorts2 = new short[shortLen + 2];
            System.arraycopy(shorts, 0, shorts2, 1, shortLen);
            assertEquals("short array off len", eh, f.hashShorts(shorts2, 1, shortLen));


            char[] chars = new char[shortLen];
            bb.asCharBuffer().get(chars);
            assertEquals("char array", eh, f.hashChars(chars));

            char[] chars2 = new char[shortLen + 2];
            System.arraycopy(chars, 0, chars2, 1, shortLen);
            assertEquals("char array off len", eh, f.hashChars(chars2, 1, shortLen));
        }

        if ((len & 3) == 0) {
            int intLen = len / 4;
            int[] ints = new int[intLen];
            bb.asIntBuffer().get(ints);
            assertEquals("int array", eh, f.hashInts(ints));

            int[] ints2 = new int[intLen + 2];
            System.arraycopy(ints, 0, ints2, 1, intLen);
            assertEquals("int array off len", eh, f.hashInts(ints2, 1, intLen));
        }

        if ((len & 7) == 0) {
            int longLen = len / 8;
            long[] longs = new long[longLen];
            bb.asLongBuffer().get(longs);
            assertEquals("long array", eh, f.hashLongs(longs));

            long[] longs2 = new long[longLen + 2];
            System.arraycopy(longs, 0, longs2, 1, longLen);
            assertEquals("long array off len", eh, f.hashLongs(longs2, 1, longLen));
        }
    }

    private static void testByteBuffers(LongHashFunction f, long eh, int len, ByteBuffer bb) {
        bb.order(LITTLE_ENDIAN);
        assertEquals("byte buffer little endian", eh, f.hashBytes(bb));
        ByteBuffer bb2 = ByteBuffer.allocate(len + 2).order(LITTLE_ENDIAN);
        bb2.position(1);
        bb2.put(bb);
        assertEquals("byte buffer little endian off len", eh, f.hashBytes(bb2, 1, len));

        bb.order(BIG_ENDIAN).clear();

        assertEquals("byte buffer big endian", eh, f.hashBytes(bb));
        bb2.order(BIG_ENDIAN);
        assertEquals("byte buffer big endian off len", eh, f.hashBytes(bb2, 1, len));

        bb.order(nativeOrder()).clear();
    }

    private static void testCharSequences(LongHashFunction f, long eh, int len, ByteBuffer bb) {
        if ((len & 1) == 0) {
            String s = bb.asCharBuffer().toString();
            assertEquals("string", eh, f.hashChars(s));

            StringBuilder sb = new StringBuilder();
            sb.append(s);
            assertEquals("string builder", eh, f.hashChars(sb));

            sb.insert(0, 'a');
            sb.append('b');
            assertEquals("string builder off len", eh, f.hashChars(sb, 1, len / 2));

            // Test for OpenJDK < 7u6, where substring wasn't copied char[] array
            assertEquals("substring", eh, f.hashChars(sb.toString().substring(1, len / 2 + 1)));

            if (len >= 2) {
                bb.order(nonNativeOrder());
                String s2 = bb.asCharBuffer().toString();
                assert s.charAt(0) != bb.getChar(0);

                long hashCharsActual = f.hashChars(s2);
                assertNotEquals("string wrong order", eh, hashCharsActual);

                long toCharSequenceActual = f.hash(s2, Access.toCharSequence(nonNativeOrder()), 0, len);
                assertEquals("string wrong order fixed", eh, toCharSequenceActual);

                bb.order(nativeOrder()).clear();
            }
        }
    }

    private static void testMemory(LongHashFunction f, long eh, int len, ByteBuffer bb) {
        ByteBuffer directBB = ByteBuffer.allocateDirect(len);
        directBB.put(bb);
        assertEquals("memory", eh, f.hashMemory(((DirectBuffer) directBB).address(), len));
        bb.clear();
    }
}

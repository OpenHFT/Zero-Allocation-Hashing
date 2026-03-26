/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.jupiter.api.Assertions.*;

class LongTupleHashFunctionTest {

    private static ByteOrder nonNativeOrder() {
        return nativeOrder() == LITTLE_ENDIAN ? BIG_ENDIAN : LITTLE_ENDIAN;
    }

    public static void test(LongTupleHashFunction f, byte[] data, long[] eh) {
        int len = data.length;

        if (len == 0) {
            testBits(f);
            testException(f);
        }

        testVoid(f, eh, len);
        testBoolean(f, len);
        ByteBuffer bb = ByteBuffer.wrap(data).order(nativeOrder());
        testPrimitives(f, eh, len, bb);
        testNegativePrimitives(f);
        testArrays(f, data, eh, len, bb);
        testByteBuffers(f, eh, len, bb);
        testCharSequences(f, eh, len, bb);
        testLatin1String(f, data);
        testMemory(f, eh, len, bb);
    }

    private static void testBits(LongTupleHashFunction f) {
        assertTrue(f.bitsLength() > 64, "bits should be more than 64");
        assertEquals((f.bitsLength() + 63) / 64, f.newResultArray().length, "tuple length");
        assertTrue(f.bitsLength() % 8 == 0, "mutiple of 8");
    }

    private static void testException(LongTupleHashFunction f) {
        boolean ok = false;
        try {
            f.hashBytes(new byte[0], null);
        } catch (NullPointerException expected) {
            ok = true;
        } catch (Throwable e) {
            fail("unexpected exception: " + e.toString());
        }
        assertTrue(ok, "should throw NullPointerException");

        ok = false;
        try {
            f.hashBytes(new byte[0], new long[1]);
        } catch (IllegalArgumentException expected) {
            ok = true;
        } catch (Throwable e) {
            fail("unexpected exception: " + e.toString());
        }
        assertTrue(ok, "should throw IllegalArgumentException");

        // no exception with larger array
        long[] r1 = f.hashBytes(new byte[1]);
        long[] r2 = new long[r1.length + 1];
        f.hashBytes(new byte[1], r2);
        for (int i = 0; i < r1.length; ++i) {
            assertEquals(r1[i], r2[i], "compare element[" + i + "] for larger result array");
        }
    }

    private static void testVoid(LongTupleHashFunction f, long[] eh, int len) {
        if (len == 0) {
            long[] r1 = f.hashVoid();
            long[] r2 = f.hashVoid();
            assertNotSame(r1, r2, "return different instance");
            assertArrayEquals(eh, r1, "void once");
            assertArrayEquals(eh, r2, "void twice");
        }
    }

    private static void testBoolean(LongTupleHashFunction f, int len) {
        if (len != 1)
            return;
        for (boolean b : new boolean[]{true, false}) {
            boolean[] a = {b};
            long[] single = f.hashBoolean(b);
            long[] array = f.hashBooleans(a);
            assertArrayEquals(single, array, "testBoolean array");
            assertArrayEquals(single, f.hash(a, UnsafeAccess.unsafe(), UnsafeAccess.BOOLEAN_BASE, 1L), "testBoolean unsafe");
        }
    }

    private static void testPrimitives(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        long[] actual;
        if (len == 1) {
            actual = f.hashByte(bb.get(0));
            assertArrayEquals(eh, actual, "byte hash");
        }

        if (len == 2) {
            actual = f.hashShort(bb.getShort(0));
            assertArrayEquals(eh, actual, "short hash");
            actual = f.hashChar(bb.getChar(0));
            assertArrayEquals(eh, actual, "char hash");
        }

        if (len == 4) {
            actual = f.hashInt(bb.getInt(0));
            assertArrayEquals(eh, actual, "int hash");
        }
        if (len == 8) {
            actual = f.hashLong(bb.getLong(0));
            assertArrayEquals(eh, actual, "long hash");
        }
    }

    private static void testNegativePrimitives(LongTupleHashFunction f) {
        byte[] bytes = new byte[8];
        Arrays.fill(bytes, (byte) -1);
        long[] oneByteExpected = f.hashBytes(bytes, 0, 1);
        long[] twoByteExpected = f.hashBytes(bytes, 0, 2);
        long[] fourByteExpected = f.hashBytes(bytes, 0, 4);
        long[] eightByteExpected = f.hashBytes(bytes);
        assertArrayEquals(oneByteExpected, f.hashByte((byte) -1), "byte hash neg");
        assertArrayEquals(twoByteExpected, f.hashShort((short) -1), "short hash neg");
        assertArrayEquals(twoByteExpected, f.hashChar((char) -1), "char hash neg");
        assertArrayEquals(fourByteExpected, f.hashInt(-1), "int hash neg");
        assertArrayEquals(eightByteExpected, f.hashLong(-1L), "long hash neg");
    }

    private static void testArrays(LongTupleHashFunction f, byte[] data, long[] eh, int len,
                                   ByteBuffer bb) {
        assertArrayEquals(eh, f.hashBytes(data), "byte array");

        byte[] data2 = new byte[len + 2];
        System.arraycopy(data, 0, data2, 1, len);
        assertArrayEquals(eh, f.hashBytes(data2, 1, len), "byte array off len");

        if ((len & 1) == 0) {
            int shortLen = len / 2;

            short[] shorts = new short[shortLen];
            bb.asShortBuffer().get(shorts);
            assertArrayEquals(eh, f.hashShorts(shorts), "short array");

            short[] shorts2 = new short[shortLen + 2];
            System.arraycopy(shorts, 0, shorts2, 1, shortLen);
            assertArrayEquals(eh, f.hashShorts(shorts2, 1, shortLen), "short array off len");

            char[] chars = new char[shortLen];
            bb.asCharBuffer().get(chars);
            assertArrayEquals(eh, f.hashChars(chars), "char array");

            char[] chars2 = new char[shortLen + 2];
            System.arraycopy(chars, 0, chars2, 1, shortLen);
            assertArrayEquals(eh, f.hashChars(chars2, 1, shortLen), "char array off len");
        }

        if ((len & 3) == 0) {
            int intLen = len / 4;
            int[] ints = new int[intLen];
            bb.asIntBuffer().get(ints);
            assertArrayEquals(eh, f.hashInts(ints), "int array");

            int[] ints2 = new int[intLen + 2];
            System.arraycopy(ints, 0, ints2, 1, intLen);
            assertArrayEquals(eh, f.hashInts(ints2, 1, intLen), "int array off len");
        }

        if ((len & 7) == 0) {
            int longLen = len / 8;
            long[] longs = new long[longLen];
            bb.asLongBuffer().get(longs);
            assertArrayEquals(eh, f.hashLongs(longs), "long array");

            long[] longs2 = new long[longLen + 2];
            System.arraycopy(longs, 0, longs2, 1, longLen);
            assertArrayEquals(eh, f.hashLongs(longs2, 1, longLen), "long array off len");
        }
    }

    private static void testByteBuffers(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        // To Support IBM JDK7, methods of Buffer#position(int) and Buffer#clear() for a ByteBuffer
        // object need to be invoked from a parent Buffer object explicitly.

        bb.order(LITTLE_ENDIAN);
        assertArrayEquals(eh, f.hashBytes(bb), "byte buffer little endian");
        ByteBuffer bb2 = ByteBuffer.allocate(len + 2).order(LITTLE_ENDIAN);
        ((Buffer) bb2).position(1);
        bb2.put(bb);
        assertArrayEquals(eh, f.hashBytes(bb2, 1, len), "byte buffer little endian off len");

        ((Buffer) bb.order(BIG_ENDIAN)).clear();

        assertArrayEquals(eh, f.hashBytes(bb), "byte buffer big endian");
        bb2.order(BIG_ENDIAN);
        assertArrayEquals(eh, f.hashBytes(bb2, 1, len), "byte buffer big endian off len");

        ((Buffer) bb.order(nativeOrder())).clear();
    }

    private static void testCharSequences(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        if ((len & 1) == 0) {
            String s = bb.asCharBuffer().toString();
            assertArrayEquals(eh, f.hashChars(s), "string");

            StringBuilder sb = new StringBuilder();
            sb.append(s);
            assertArrayEquals(eh, f.hashChars(sb), "string builder");

            sb.insert(0, 'a');
            sb.append('b');
            assertArrayEquals(eh, f.hashChars(sb, 1, len / 2), "string builder off len");

            // Test for OpenJDK < 7u6, where substring wasn't copied char[] array
            assertArrayEquals(eh, f.hashChars(sb.toString().substring(1, len / 2 + 1)), "substring");

            if (len >= 2) {
                bb.order(nonNativeOrder());
                String s2 = bb.asCharBuffer().toString();
                assert s.charAt(0) != bb.getChar(0);

                long[] hashCharsActual = f.hashChars(s2);
                assertThat("string wrong order", hashCharsActual, not(equalTo(eh)));

                long[] toCharSequenceActual = f.hash(s2, Access.toCharSequence(nonNativeOrder()), 0, len);
                assertArrayEquals(eh, toCharSequenceActual, "string wrong order fixed");

                ((Buffer) bb.order(nativeOrder())).clear();
            }
        }
    }

    private static void testMemory(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        ByteBuffer directBB = ByteBuffer.allocateDirect(len);
        directBB.put(bb);
        assertArrayEquals(eh, f.hashMemory(Util.getDirectBufferAddress(directBB), len), "memory");
        ((Buffer) bb).clear();
    }

    private static void testLatin1String(LongTupleHashFunction f, byte[] data) {
        // test for compact string from JDK 9
        try {
            String inputStr = new String(data, "ISO-8859-1");
            char[] inputCharArray = new char[data.length];
            for (int i = 0; i < data.length; ++i) {
                inputCharArray[i] = (char) (data[i] & 0xFF);
            }
            char[] inputCharArray2 = new char[data.length];
            for (int i = 0; i < data.length; ++i) {
                inputCharArray2[i] = (char) (data[i] & 0xFF);
            }
            assertArrayEquals(f.hashChars(inputStr), f.hashChars(inputCharArray));
        } catch (Exception e) {
            fail("exception when test latin1 string:" + e.toString());
        }
    }
}

package net.openhft.hashing;

import sun.nio.ch.DirectBuffer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static java.nio.ByteOrder.nativeOrder;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;

public class LongTupleHashFunctionTest {

    private static ByteOrder nonNativeOrder() {
        return nativeOrder() == LITTLE_ENDIAN ? BIG_ENDIAN : LITTLE_ENDIAN;
    }

    public static void test(LongTupleHashFunction f, byte[] data, long[] eh) {
        testBits(f);

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

	LongHashFunctionTest.test(f, data, eh[0]); // test as LongHashFunction
    }

    private static void testBits(LongTupleHashFunction f) {
        assertTrue("bits should be more than 64", f.bits() > 64);
        assertEquals("tuple length", (f.bits() + 63) / 64, f.newLongTuple().length);

        final int bitsInHighM1 = (f.bits() - 1) & 63;
        assertEquals("mask should be as default", ((1L << bitsInHighM1) << 1) - 1, f.highMask());
    }

    private static void testVoid(LongTupleHashFunction f, long[] eh, int len) {
        if (len == 0)
            assertArrayEquals("void", eh, f.hashTupleVoid());
    }
    
    public static void testBoolean(LongTupleHashFunction f, int len) {
        if (len != 1)
            return;
        for (boolean b : new boolean[] {true, false}) {
            boolean[] a = {b};
            long[] single = f.hashTupleBoolean(b);
            long[] array = f.hashTupleBooleans(a);
            assertArrayEquals(single, array);
            assertArrayEquals(single, f.hashTuple(a, UnsafeAccess.unsafe(), UnsafeAccess.BOOLEAN_BASE, 1L));
        }
    }

    private static void testPrimitives(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        long[] actual;
        if (len == 1) {
            actual = f.hashTupleByte(bb.get(0));
            assertArrayEquals("byte hash", eh, actual);
        }

        if (len == 2) {
            actual = f.hashTupleShort(bb.getShort(0));
            assertArrayEquals("short hash", eh, actual);
            actual = f.hashTupleChar(bb.getChar(0));
            assertArrayEquals("char hash", eh, actual);
        }

        if (len == 4) {
            actual = f.hashTupleInt(bb.getInt(0));
            assertArrayEquals("int hash", eh, actual);
        }
        if (len == 8) {
            actual = f.hashTupleLong(bb.getLong(0));
            assertArrayEquals("long hash", eh, actual);
        }
    }

    private static void testNegativePrimitives(LongTupleHashFunction f) {
        byte[] bytes = new byte[8];
        Arrays.fill(bytes, (byte) -1);
        long[] oneByteExpected = f.hashTupleBytes(bytes, 0, 1);
        long[] twoByteExpected = f.hashTupleBytes(bytes, 0, 2);
        long[] fourByteExpected = f.hashTupleBytes(bytes, 0, 4);
        long[] eightByteExpected = f.hashTupleBytes(bytes);
        assertArrayEquals("byte hash", oneByteExpected, f.hashTupleByte((byte) -1));
        assertArrayEquals("short hash", twoByteExpected, f.hashTupleShort((short) -1));
        assertArrayEquals("char hash", twoByteExpected, f.hashTupleChar((char) -1));
        assertArrayEquals("int hash", fourByteExpected, f.hashTupleInt(-1));
        assertArrayEquals("long hash", eightByteExpected, f.hashTupleLong(-1L));
    }

    private static void testArrays(LongTupleHashFunction f, byte[] data, long[] eh, int len,
                                   ByteBuffer bb) {
        assertArrayEquals("byte array", eh, f.hashTupleBytes(data));

        byte[] data2 = new byte[len + 2];
        System.arraycopy(data, 0, data2, 1, len);
        assertArrayEquals("byte array off len", eh, f.hashTupleBytes(data2, 1, len));

        if ((len & 1) == 0) {
            int shortLen = len / 2;

            short[] shorts = new short[shortLen];
            bb.asShortBuffer().get(shorts);
            assertArrayEquals("short array", eh, f.hashTupleShorts(shorts));

            short[] shorts2 = new short[shortLen + 2];
            System.arraycopy(shorts, 0, shorts2, 1, shortLen);
            assertArrayEquals("short array off len", eh, f.hashTupleShorts(shorts2, 1, shortLen));


            char[] chars = new char[shortLen];
            bb.asCharBuffer().get(chars);
            assertArrayEquals("char array", eh, f.hashTupleChars(chars));

            char[] chars2 = new char[shortLen + 2];
            System.arraycopy(chars, 0, chars2, 1, shortLen);
            assertArrayEquals("char array off len", eh, f.hashTupleChars(chars2, 1, shortLen));
        }

        if ((len & 3) == 0) {
            int intLen = len / 4;
            int[] ints = new int[intLen];
            bb.asIntBuffer().get(ints);
            assertArrayEquals("int array", eh, f.hashTupleInts(ints));

            int[] ints2 = new int[intLen + 2];
            System.arraycopy(ints, 0, ints2, 1, intLen);
            assertArrayEquals("int array off len", eh, f.hashTupleInts(ints2, 1, intLen));
        }

        if ((len & 7) == 0) {
            int longLen = len / 8;
            long[] longs = new long[longLen];
            bb.asLongBuffer().get(longs);
            assertArrayEquals("long array", eh, f.hashTupleLongs(longs));

            long[] longs2 = new long[longLen + 2];
            System.arraycopy(longs, 0, longs2, 1, longLen);
            assertArrayEquals("long array off len", eh, f.hashTupleLongs(longs2, 1, longLen));
        }
    }

    private static void testByteBuffers(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        bb.order(LITTLE_ENDIAN);
        assertArrayEquals("byte buffer little endian", eh, f.hashTupleBytes(bb));
        ByteBuffer bb2 = ByteBuffer.allocate(len + 2).order(LITTLE_ENDIAN);
        bb2.position(1);
        bb2.put(bb);
        assertArrayEquals("byte buffer little endian off len", eh, f.hashTupleBytes(bb2, 1, len));

        bb.order(BIG_ENDIAN).clear();

        assertArrayEquals("byte buffer big endian", eh, f.hashTupleBytes(bb));
        bb2.order(BIG_ENDIAN);
        assertArrayEquals("byte buffer big endian off len", eh, f.hashTupleBytes(bb2, 1, len));

        bb.order(nativeOrder()).clear();
    }

    private static void testCharSequences(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        if ((len & 1) == 0) {
            String s = bb.asCharBuffer().toString();
            assertArrayEquals("string", eh, f.hashTupleChars(s));

            StringBuilder sb = new StringBuilder();
            sb.append(s);
            assertArrayEquals("string builder", eh, f.hashTupleChars(sb));

            sb.insert(0, 'a');
            sb.append('b');
            assertArrayEquals("string builder off len", eh, f.hashTupleChars(sb, 1, len / 2));

            // Test for OpenJDK < 7u6, where substring wasn't copied char[] array
            assertArrayEquals("substring", eh, f.hashTupleChars(sb.toString().substring(1, len / 2 + 1)));

            if (len >= 2) {
                bb.order(BIG_ENDIAN);
                String s2 = bb.asCharBuffer().toString();
                assert s.charAt(0) != bb.getChar(0);

                long[] hashCharsActual = f.hashTupleChars(s2);
                assertThat("string wrong order", hashCharsActual, not(equalTo(eh)));

                long[] toCharSequenceActual = f.hashTuple(s2, Access.toCharSequence(nonNativeOrder()), 0, len);
                assertArrayEquals("string wrong order fixed", eh, toCharSequenceActual);

                bb.order(nativeOrder()).clear();
            }
        }
    }

    private static void testMemory(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        ByteBuffer directBB = ByteBuffer.allocateDirect(len);
        directBB.put(bb);
        assertArrayEquals("memory", eh, f.hashTupleMemory(((DirectBuffer) directBB).address(), len));
        bb.clear();
    }
}

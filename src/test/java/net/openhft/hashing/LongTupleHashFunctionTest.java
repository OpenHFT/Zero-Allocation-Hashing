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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class LongTupleHashFunctionTest {

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
        testMemory(f, eh, len, bb);
    }

    private static void testBits(LongTupleHashFunction f) {
        assertTrue("bits should be more than 64", f.bitsLength() > 64);
        assertEquals("tuple length", (f.bitsLength() + 63) / 64, f.newResultArray().length);
        assertTrue("mutiple of 8", f.bitsLength() % 8 == 0);
    }

    private static void testException(LongTupleHashFunction f) {
        boolean ok = false;
        try {
            f.hashBytes(new byte[0], null);
        } catch (NullPointerException expected) {
            ok = true;
        } catch (Throwable e) {
            fail(e.toString());
        }
        assertTrue("should throw NullPointerException", ok);

        ok = false;
        try {
            f.hashBytes(new byte[0], new long[1]);
        } catch (IllegalArgumentException expected) {
            ok = true;
        } catch (Throwable e) {
            fail(e.toString());
        }
        assertTrue("should throw IllegalArgumentException", ok);

        // no exception with larger array
        long[] r1 = f.hashBytes(new byte[1]);
        long[] r2 = new long[r1.length + 1];
        f.hashBytes(new byte[1], r2);
        for (int i = 0; i < r1.length; ++i) {
            assertEquals(r1[i], r2[i]);
        }
    }

    private static void testVoid(LongTupleHashFunction f, long[] eh, int len) {
        if (len == 0) {
            long[] r1 = f.hashVoid();
            long[] r2 = f.hashVoid();
            assertNotSame("return different instance", r1, r2);
            assertArrayEquals("void once", eh, r1);
            assertArrayEquals("void twice", eh, r2);
        }
    }

    public static void testBoolean(LongTupleHashFunction f, int len) {
        if (len != 1)
            return;
        for (boolean b : new boolean[] {true, false}) {
            boolean[] a = {b};
            long[] single = f.hashBoolean(b);
            long[] array = f.hashBooleans(a);
            assertArrayEquals(single, array);
            assertArrayEquals(single, f.hash(a, UnsafeAccess.unsafe(), UnsafeAccess.BOOLEAN_BASE, 1L));
        }
    }

    private static void testPrimitives(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        long[] actual;
        if (len == 1) {
            actual = f.hashByte(bb.get(0));
            assertArrayEquals("byte hash", eh, actual);
        }

        if (len == 2) {
            actual = f.hashShort(bb.getShort(0));
            assertArrayEquals("short hash", eh, actual);
            actual = f.hashChar(bb.getChar(0));
            assertArrayEquals("char hash", eh, actual);
        }

        if (len == 4) {
            actual = f.hashInt(bb.getInt(0));
            assertArrayEquals("int hash", eh, actual);
        }
        if (len == 8) {
            actual = f.hashLong(bb.getLong(0));
            assertArrayEquals("long hash", eh, actual);
        }
    }

    private static void testNegativePrimitives(LongTupleHashFunction f) {
        byte[] bytes = new byte[8];
        Arrays.fill(bytes, (byte) -1);
        long[] oneByteExpected = f.hashBytes(bytes, 0, 1);
        long[] twoByteExpected = f.hashBytes(bytes, 0, 2);
        long[] fourByteExpected = f.hashBytes(bytes, 0, 4);
        long[] eightByteExpected = f.hashBytes(bytes);
        assertArrayEquals("byte hash", oneByteExpected, f.hashByte((byte) -1));
        assertArrayEquals("short hash", twoByteExpected, f.hashShort((short) -1));
        assertArrayEquals("char hash", twoByteExpected, f.hashChar((char) -1));
        assertArrayEquals("int hash", fourByteExpected, f.hashInt(-1));
        assertArrayEquals("long hash", eightByteExpected, f.hashLong(-1L));
    }

    private static void testArrays(LongTupleHashFunction f, byte[] data, long[] eh, int len,
                                   ByteBuffer bb) {
        assertArrayEquals("byte array", eh, f.hashBytes(data));

        byte[] data2 = new byte[len + 2];
        System.arraycopy(data, 0, data2, 1, len);
        assertArrayEquals("byte array off len", eh, f.hashBytes(data2, 1, len));

        if ((len & 1) == 0) {
            int shortLen = len / 2;

            short[] shorts = new short[shortLen];
            bb.asShortBuffer().get(shorts);
            assertArrayEquals("short array", eh, f.hashShorts(shorts));

            short[] shorts2 = new short[shortLen + 2];
            System.arraycopy(shorts, 0, shorts2, 1, shortLen);
            assertArrayEquals("short array off len", eh, f.hashShorts(shorts2, 1, shortLen));


            char[] chars = new char[shortLen];
            bb.asCharBuffer().get(chars);
            assertArrayEquals("char array", eh, f.hashChars(chars));

            char[] chars2 = new char[shortLen + 2];
            System.arraycopy(chars, 0, chars2, 1, shortLen);
            assertArrayEquals("char array off len", eh, f.hashChars(chars2, 1, shortLen));
        }

        if ((len & 3) == 0) {
            int intLen = len / 4;
            int[] ints = new int[intLen];
            bb.asIntBuffer().get(ints);
            assertArrayEquals("int array", eh, f.hashInts(ints));

            int[] ints2 = new int[intLen + 2];
            System.arraycopy(ints, 0, ints2, 1, intLen);
            assertArrayEquals("int array off len", eh, f.hashInts(ints2, 1, intLen));
        }

        if ((len & 7) == 0) {
            int longLen = len / 8;
            long[] longs = new long[longLen];
            bb.asLongBuffer().get(longs);
            assertArrayEquals("long array", eh, f.hashLongs(longs));

            long[] longs2 = new long[longLen + 2];
            System.arraycopy(longs, 0, longs2, 1, longLen);
            assertArrayEquals("long array off len", eh, f.hashLongs(longs2, 1, longLen));
        }
    }

    private static void testByteBuffers(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        // To Support IBM JDK7, methods of Buffer#position(int) and Buffer#clear() for a ByteBuffer
        // object need to be invoked from a parent Buffer object explicitly.

        bb.order(LITTLE_ENDIAN);
        assertArrayEquals("byte buffer little endian", eh, f.hashBytes(bb));
        ByteBuffer bb2 = ByteBuffer.allocate(len + 2).order(LITTLE_ENDIAN);
        ((Buffer)bb2).position(1);
        bb2.put(bb);
        assertArrayEquals("byte buffer little endian off len", eh, f.hashBytes(bb2, 1, len));

        ((Buffer)bb.order(BIG_ENDIAN)).clear();

        assertArrayEquals("byte buffer big endian", eh, f.hashBytes(bb));
        bb2.order(BIG_ENDIAN);
        assertArrayEquals("byte buffer big endian off len", eh, f.hashBytes(bb2, 1, len));

        ((Buffer)bb.order(nativeOrder())).clear();
    }

    private static void testCharSequences(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        if ((len & 1) == 0) {
            String s = bb.asCharBuffer().toString();
            assertArrayEquals("string", eh, f.hashChars(s));

            StringBuilder sb = new StringBuilder();
            sb.append(s);
            assertArrayEquals("string builder", eh, f.hashChars(sb));

            sb.insert(0, 'a');
            sb.append('b');
            assertArrayEquals("string builder off len", eh, f.hashChars(sb, 1, len / 2));

            // Test for OpenJDK < 7u6, where substring wasn't copied char[] array
            assertArrayEquals("substring", eh, f.hashChars(sb.toString().substring(1, len / 2 + 1)));

            if (len >= 2) {
                bb.order(nonNativeOrder());
                String s2 = bb.asCharBuffer().toString();
                assert s.charAt(0) != bb.getChar(0);

                long[] hashCharsActual = f.hashChars(s2);
                assertThat("string wrong order", hashCharsActual, not(equalTo(eh)));

                long[] toCharSequenceActual = f.hash(s2, Access.toCharSequence(nonNativeOrder()), 0, len);
                assertArrayEquals("string wrong order fixed", eh, toCharSequenceActual);

                ((Buffer)bb.order(nativeOrder())).clear();
            }
        }
    }

    private static void testMemory(LongTupleHashFunction f, long[] eh, int len, ByteBuffer bb) {
        ByteBuffer directBB = ByteBuffer.allocateDirect(len);
        directBB.put(bb);
        assertArrayEquals("memory", eh, f.hashMemory(Util.getDirectBufferAddress(directBB), len));
        ((Buffer)bb).clear();
    }
}

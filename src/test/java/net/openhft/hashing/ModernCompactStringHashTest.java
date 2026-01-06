/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class ModernCompactStringHashTest {

    private static boolean isCompactStringsVm() {
        return System.getProperty("java.version").compareTo("1.9") >= 0;
    }

    private static boolean compactStringsEnabled() {
        if (!isCompactStringsVm()) {
            return false;
        }
        try {
            java.lang.reflect.Field field = ModernCompactStringHash.class.getDeclaredField("enableCompactStrings");
            field.setAccessible(true);
            return field.getBoolean(null);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static boolean isCompactLatin1(String s) {
        if (!compactStringsEnabled()) {
            return false;
        }
        try {
            java.lang.reflect.Field offsetField = ModernCompactStringHash.class.getDeclaredField("valueOffset");
            offsetField.setAccessible(true);
            long valueOffset = offsetField.getLong(null);
            Object value = UnsafeAccess.UNSAFE.getObject(s, valueOffset);
            return value instanceof byte[] && ((byte[]) value).length == s.length();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    public void longHashReturnsVoidWhenLenIsZero() {
        assumeTrue(isCompactLatin1("Cafe"));
        RecordingLongHashFunction hash = new RecordingLongHashFunction();

        long actual = ModernCompactStringHash.INSTANCE.longHash("abc", hash, 0, 0);

        assertTrue(hash.hashVoidCalled, "hashVoid should be called when input length is 0");
        assertEquals(RecordingLongHashFunction.HASH_VOID_RESULT, actual, "longHash should return HASH_VOID_RESULT (0x5678) for zero-length input");
        assertEquals(0L, hash.lastLength, "zero length should be passed to hash function");
    }

    @Test
    public void longHashUsesCompactAccessForLatin1() {
        assumeTrue(isCompactLatin1("Cafe"));
        RecordingLongHashFunction hash = new RecordingLongHashFunction();

        long actual = ModernCompactStringHash.INSTANCE.longHash("Cafe", hash, 1, 2);

        assumeTrue(hash.lastAccess == CompactLatin1CharSequenceAccess.INSTANCE, "CompactLatin1CharSequenceAccess should be used for Latin1 compact strings");
        assertEquals(RecordingLongHashFunction.HASH_RESULT, actual, "longHash should return HASH_RESULT (0x1234) for compact Latin1 string");
        assertEquals(2L, hash.lastOffset, "byte offset 2 should be passed to hash function (pos=1, 2 bytes per char)");
        assertEquals(4L, hash.lastLength, "byte length 4 should be passed to hash function (len=2, 2 bytes per char)");
    }

    @Test
    public void longHashFallsBackToUnsafeForNonLatin1() {
        assumeTrue(isCompactStringsVm());
        RecordingLongHashFunction hash = new RecordingLongHashFunction();

        ModernCompactStringHash.INSTANCE.longHash("ab\u0100c", hash, 0, 4);

        assertSame(UnsafeAccess.INSTANCE, hash.lastAccess, "UnsafeAccess should be used for non-Latin1 strings containing characters > 0xFF");
        assertEquals(UnsafeAccess.BYTE_BASE, hash.lastOffset, "byte array base offset should be passed to hash for UTF-16 encoding");
        assertEquals(8L, hash.lastLength, "byte length 8 should be passed to hash function (len=4, 2 bytes per UTF-16 char)");
    }

    @Test
    public void longHashValidatesOffsets() {
        assumeTrue(isCompactStringsVm());
        assertThrows(IndexOutOfBoundsException.class,
                () -> ModernCompactStringHash.INSTANCE.longHash("abc", new RecordingLongHashFunction(), 3, 1),
                "longHash should throw IndexOutOfBoundsException when off=3, len=1 exceeds string length 3");
    }

    @Test
    public void tupleHashUsesCompactAccessForLatin1() {
        assumeTrue(isCompactStringsVm());
        RecordingLongTupleHashFunction hash = new RecordingLongTupleHashFunction();
        long[] out = new long[hash.newResultArray().length];

        ModernCompactStringHash.INSTANCE.hash("Cafe", hash, 1, 2, out);

        assumeTrue(hash.lastAccess == CompactLatin1CharSequenceAccess.INSTANCE, "CompactLatin1CharSequenceAccess should be used for Latin1 compact strings in tuple hash");
        assertEquals(2L, hash.lastOffset, "byte offset 2 should be passed to tuple hash function (pos=1, 2 bytes per char)");
        assertEquals(4L, hash.lastLength, "byte length 4 should be passed to tuple hash function (len=2, 2 bytes per char)");
        assertEquals(RecordingLongTupleHashFunction.RESULT_VALUE, out[0], "tuple hash should store RESULT_VALUE (0x2233) in output array");
    }

    @Test
    public void tupleHashReturnsVoidWhenLenIsZero() {
        assumeTrue(isCompactStringsVm());
        RecordingLongTupleHashFunction hash = new RecordingLongTupleHashFunction();
        long[] out = new long[hash.newResultArray().length];

        ModernCompactStringHash.INSTANCE.hash("abc", hash, 0, 0, out);

        assertTrue(hash.hashVoidCalled, "hashVoid should be called when tuple hash input length is 0");
        assertEquals(RecordingLongTupleHashFunction.VOID_RESULT_VALUE, out[0], "tuple hash should store VOID_RESULT_VALUE (0x3344) in output array for zero-length input");
    }

    @Test
    public void tupleHashFallsBackToUnsafeForNonLatin1() {
        assumeTrue(isCompactStringsVm());
        RecordingLongTupleHashFunction hash = new RecordingLongTupleHashFunction();
        long[] out = new long[hash.newResultArray().length];

        ModernCompactStringHash.INSTANCE.hash("ab\u0100c", hash, 0, 4, out);

        assertSame(UnsafeAccess.INSTANCE, hash.lastAccess, "UnsafeAccess should be used for tuple hash of non-Latin1 strings containing characters > 0xFF");
        assertEquals(UnsafeAccess.BYTE_BASE, hash.lastOffset, "byte array base offset should be passed to tuple hash for UTF-16 encoding");
        assertEquals(8L, hash.lastLength, "byte length 8 should be passed to tuple hash function (len=4, 2 bytes per UTF-16 char)");
    }

    private static final class RecordingLongHashFunction extends LongHashFunction {
        static final long HASH_RESULT = 0x1234L;
        static final long HASH_VOID_RESULT = 0x5678L;
        private static final long serialVersionUID = 1L;

        Access<?> lastAccess;
        long lastOffset;
        long lastLength;
        boolean hashVoidCalled;

        @Override
        public long hashLong(long input) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long hashInt(int input) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long hashShort(short input) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long hashChar(char input) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long hashByte(byte input) {
            throw new UnsupportedOperationException();
        }

        @Override
        public long hashVoid() {
            hashVoidCalled = true;
            lastAccess = null;
            lastOffset = 0L;
            lastLength = 0L;
            return HASH_VOID_RESULT;
        }

        @Override
        public <T> long hash(T input, Access<T> access, long off, long len) {
            lastAccess = access;
            lastOffset = off;
            lastLength = len;
            return HASH_RESULT;
        }
    }

    private static final class RecordingLongTupleHashFunction extends LongTupleHashFunction {
        static final long RESULT_VALUE = 0x2233L;
        static final long VOID_RESULT_VALUE = 0x3344L;
        private static final long serialVersionUID = 1L;

        Access<?> lastAccess;
        long lastOffset;
        long lastLength;
        boolean hashVoidCalled;

        @Override
        public int bitsLength() {
            return 128;
        }

        @Override
        public void hashLong(long input, long[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void hashInt(int input, long[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void hashShort(short input, long[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void hashChar(char input, long[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void hashByte(byte input, long[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void hashVoid(long[] result) {
            hashVoidCalled = true;
            result[0] = VOID_RESULT_VALUE;
            if (result.length > 1) {
                result[1] = 0L;
            }
        }

        @Override
        public <T> void hash(T input, Access<T> access, long off, long len, long[] result) {
            lastAccess = access;
            lastOffset = off;
            lastLength = len;
            result[0] = RESULT_VALUE;
            if (result.length > 1) {
                result[1] = 0L;
            }
        }
    }
}

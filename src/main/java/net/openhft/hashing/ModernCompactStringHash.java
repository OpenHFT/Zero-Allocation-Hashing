package net.openhft.hashing;

import java.lang.reflect.Field;
import javax.annotation.ParametersAreNonnullByDefault;
import static net.openhft.hashing.UnsafeAccess.*;
import static net.openhft.hashing.Util.*;

@ParametersAreNonnullByDefault
enum ModernCompactStringHash implements StringHash {
    INSTANCE;

    private static final long valueOffset;
    private static final boolean enableCompactStrings;
    private static final Access<byte[]> compactLatin1Access
        = CompactLatin1CharSequenceAccess.INSTANCE;

    static {
        try {
            final Field valueField = String.class.getDeclaredField("value");
            valueOffset = UnsafeAccess.UNSAFE.objectFieldOffset(valueField);

            final byte[] value = (byte[]) UnsafeAccess.UNSAFE.getObject("A", valueOffset);
            enableCompactStrings = (1 == value.length);
        } catch (final NoSuchFieldException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public long longHash(final String s, final LongHashFunction hashFunction,
                    final int off, final int len) {
        final int sl = s.length();
        if (len <= 0 || sl <= 0) {
            checkArrayOffs(sl, off, len); // check as chars
            return hashFunction.hashVoid();
        } else {
            final byte[] value = (byte[]) UnsafeAccess.UNSAFE.getObject(s, valueOffset);
            if (enableCompactStrings && sl == value.length) {
                checkArrayOffs(sl, off, len); // check as chars
                // 'off' and 'len' are passed as bytes
                return hashFunction.hash(value, compactLatin1Access, (long)off*2L, (long)len*2L);
            } else {
                return hashFunction.hashBytes(value, off*2, len*2); // hash as bytes
            }
        }
    }

    @Override
    public void hash(final String s, final LongTupleHashFunction hashFunction,
                    final int off, final int len, final long[] result) {
        final int sl = s.length();
        if (len <= 0 || sl <= 0) {
            checkArrayOffs(sl, off, len); // check as chars
            hashFunction.hashVoid(result);
        } else {
            final byte[] value = (byte[]) UnsafeAccess.UNSAFE.getObject(s, valueOffset);
            if (enableCompactStrings && sl == value.length) {
                checkArrayOffs(sl, off, len); // check as chars
                // 'off' and 'len' are passed as bytes
                hashFunction.hash(value, compactLatin1Access, (long)off*2L, (long)len*2L, result);
            } else {
                hashFunction.hashBytes(value, off*2, len*2, result); // hash as bytes
            }
        }
    }
}

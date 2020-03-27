package net.openhft.hashing;

import java.nio.ByteOrder;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

import static java.nio.ByteOrder.BIG_ENDIAN;
import static java.nio.ByteOrder.LITTLE_ENDIAN;
import static net.openhft.hashing.UnsafeAccess.BYTE_BASE;

/*
 * Compress Latin1 Access
 *
 * Explaination:
 *
 * compressed idx :  0  1  2  3  4  5
 * compressed bytes: 12 34 56 78 9A BC
 *
 * compressed idx :  0     1     2     3     4     5
 * expanded index :  0  1  2  3  4  5  6  7  8  9  A  B
 * expanded LE mem:  12 00 34 00 56 00 78 00 9A 00 BC 00
 * expanded BE mem:  00 12 00 34 00 56 00 78 00 9A 00 BC
 *   align LE byte:  []    --> 0x12
 *   align BE byte:  []    --> 0x00
 * unalign LE byte:     [] --> 0x00
 * unalign BE byte:     [] --> 0x12
 *
 * compressed idx :  0     1     2     3     4     5
 * expanded index :  0  1  2  3  4  5  6  7  8  9  A  B
 * expanded LE mem:  12 00 34 00 56 00 78 00 9A 00 BC 00
 * expanded BE mem:  00 12 00 34 00 56 00 78 00 9A 00 BC
 *   align LE char:  [___]    --> 0x12
 *   align BE char:  [___]    --> 0x12
 * unalign LE char:     [___] --> 0x3400
 * unalign BE char:     [___] --> 0x1200
 *
 * compressed idx :  0     1     2     3     4     5
 * expanded index :  0  1  2  3  4  5  6  7  8  9  A  B
 * expanded LE mem:  12 00 34 00 56 00 78 00 9A 00 BC 00
 * expanded BE mem:  00 12 00 34 00 56 00 78 00 9A 00 BC
 *   align LE int :  [_________]    --> 0x340012
 *   align BE int :  [_________]    --> 0x120034
 * unalign LE int :     [_________] --> 0x56003400
 * unalign BE int :     [_________] --> 0x12003400
 *
 * compressed idx :  0     1     2     3     4     5
 * expanded index :  0  1  2  3  4  5  6  7  8  9  A  B
 * expanded LE mem:  12 00 34 00 56 00 78 00 9A 00 BC 00
 * expanded BE mem:  00 12 00 34 00 56 00 78 00 9A 00 BC
 *   align LE long:  [_____________________]    --> 0x78005600340012
 *   align BE long:  [_____________________]    --> 0x12003400560078
 * unalign LE long:     [_____________________] --> 0x9A00780056003400
 * unalign BE long:     [_____________________] --> 0x1200340056007800
 *
 * Parameters:
 *
 * Parameters must satisfy: 0 <= offset < offset + typeWidth <= input.length*2.
 * When offset + typeWidth >= (input.length + 1)*2, the behavior is undefined, throwing a exception
 * or returning dirty results.
 * When offset + typeWidth == input.length*2 + 1,
 * 1) on BE machine, the result is correct
 * 2) on LE machine, the behavior is undefined, throwing a exception or returning dirty results.
 *
 * compressed idx :  0
 * expanded index :  0  1
 * expanded LE mem:  12 00
 * expanded BE mem:  00 12
 *   align LE char:  [___]    --> 0x12
 *   align BE char:  [___]    --> 0x12
 * unalign LE char:     [_??] --> 0x??00, exception or dirty
 * unalign BE char:     [_00] --> 0x1200, correct
 *
 * Notes: This access is based on the UnsafeAccess, so only works for the native order.
 */
@ParametersAreNonnullByDefault
abstract class CompactLatin1CharSequenceAccess extends Access<byte[]> {
    @NotNull
    static final CompactLatin1CharSequenceAccess INSTANCE
        = ByteOrder.nativeOrder() == LITTLE_ENDIAN ? LittleEndian.INSTANCE : BigEndian.INSTANCE;

    @NotNull
    private static final UnsafeAccess UNSAFE = UnsafeAccess.INSTANCE;

    private static int ix(final long offset) {
        return (int) (offset >> 1);
    }

    protected static long getLong(final byte[] input, final long offset, final int offAdjust) {
        final int byteIdx = ix(offset + offAdjust);
        final int shift = ((int)offset & 1) << 3;
        final long compact = UNSAFE.getUnsignedInt(input, BYTE_BASE + byteIdx);
        long expanded = ((compact << 16) | compact) & 0xFFFF0000FFFFL;
        expanded = ((expanded << 8) | expanded) & 0xFF00FF00FF00FFL;
        return expanded << shift;
    }

    protected static int getInt(final byte[] input, final long offset, final int offAdjust) {
        final int byteIdx = ix(offset + offAdjust);
        final int shift = ((int)offset & 1) << 3;
        final int compact = UNSAFE.getUnsignedShort(input, BYTE_BASE + byteIdx);
        final int expanded = ((compact << 8) | compact) & 0xFF00FF;
        return expanded << shift;
    }

    protected static int getShort(final byte[] input, final long offset, final int offAdjust) {
        final int byteIdx = ix(offset + offAdjust);
        final int shift = ((int)offset & 1) << 3;
        return Primitives.unsignedByte(input[byteIdx]) << shift;
    }

    protected static int getByte(final byte[] input, final long offset, final int z) {
        if (z == ((int)offset & 1)) {
            return 0;
        } else {
            return Primitives.unsignedByte(input[ix(offset)]);
        }
    }

    private CompactLatin1CharSequenceAccess() {}

    @Override
    public long getUnsignedInt(final byte[] input, final long offset) {
        return Primitives.unsignedInt(getInt(input, offset));
    }

    @Override
    public int getUnsignedShort(final byte[] input, final long offset) {
        return Primitives.unsignedShort(getShort(input, offset));
    }

    @Override
    public int getUnsignedByte(final byte[] input, final long offset) {
        return Primitives.unsignedByte(getByte(input, offset));
    }

    @Override
    @NotNull
    public ByteOrder byteOrder(final byte[] input) {
        return UNSAFE.byteOrder(input);
    }

    private static class LittleEndian extends CompactLatin1CharSequenceAccess {
        private static final LittleEndian INSTANCE = new LittleEndian();

        private LittleEndian() {}

        @Override
        public long getLong(final byte[] input, final long offset) {
            return getLong(input, offset, 1);
        }

        @Override
        public int getInt(final byte[] input, final long offset) {
            return getInt(input, offset, 1);
        }

        @Override
        public int getShort(final byte[] input, final long offset) {
            return getShort(input, offset, 1);
        }

        @Override
        public int getByte(final byte[] input, final long offset) {
            return getByte(input, offset, 1);
        }
    }

    private static class BigEndian extends CompactLatin1CharSequenceAccess {
        private static final BigEndian INSTANCE = new BigEndian();

        private BigEndian() {}

        @Override
        public long getLong(final byte[] input, final long offset) {
            return getLong(input, offset, 0);
        }

        @Override
        public int getInt(final byte[] input, final long offset) {
            return getInt(input, offset, 0);
        }

        @Override
        public int getShort(final byte[] input, final long offset) {
            return getShort(input, offset, 0);
        }

        @Override
        public int getByte(final byte[] input, final long offset) {
            return getByte(input, offset, 0);
        }
    }
}

package net.openhft.hashing;

import org.jetbrains.annotations.NotNull;

import static java.nio.ByteOrder.*;

final class Util {
    static final boolean NATIVE_LITTLE_ENDIAN = nativeOrder() == LITTLE_ENDIAN;

    @NotNull
    static final StringHash VALID_STRING_HASH;
    static  {
        StringHash stringHash = null;
        try {
            if (System.getProperty("java.vm.name").contains("HotSpot")) {
                final String javaVersion = System.getProperty("java.version");
                if (javaVersion.compareTo("1.7.0_06") >= 0) {
                    if (javaVersion.compareTo("1.9") >= 0) {
                        stringHash = UnknownJvmStringHash.INSTANCE;
                    } else {
                        stringHash = ModernHotSpotStringHash.INSTANCE;
                    }
                } else {
                    stringHash = HotSpotPrior7u6StringHash.INSTANCE;
                }
            } else {
                // try to initialize this version anyway
                stringHash = HotSpotPrior7u6StringHash.INSTANCE;
            }
        } catch (final Throwable e) {
            // ignore
        } finally {
            if (null == stringHash) {
                VALID_STRING_HASH = UnknownJvmStringHash.INSTANCE;
            } else {
                VALID_STRING_HASH = stringHash;
            }
        }
    }

    static void checkArrayOffs(final int arrayLength, final int off, final int len) {
        if (len < 0 || off < 0 || off + len > arrayLength || off + len < 0)
            throw new IndexOutOfBoundsException();
    }
}

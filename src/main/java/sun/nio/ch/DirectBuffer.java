package sun.nio.ch;

/**
 * Stub for JDK internal ckass sun.nio.ch.DirectBuffer.
 * <p>
 * - When crossing compiling for Java SE 7 and 8, this stub class bypasses compiler sun-api
 *   warnings.
 * - When crossing compiling for Java SE 9+, the package 'sun.nio.ch' is not exported from
 *   'java.base' module. This stub class helps to access the class in compile-time without
 *   '--add-export' arguments and bypasses sun-api warnings.
 * - Only used methods are exported.
 * - In test and production runtime, the real class is loaded from boot classpath.
 */

public interface DirectBuffer {
    public long address();
}

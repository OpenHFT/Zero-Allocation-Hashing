package java.lang;

/**
 * Stub for JDK internal ckass java.lang.Math.
 *
 * - When crossing compiling for Java SE 7 and 8, this stub class can be used for detecting
 *   Math#multiplyHigh() method at runtime.
 * - Only used methods are exported.
 * - In test and production runtime, the real class is loaded from boot classpath.
 */

public class Math {
    public static long multiplyHigh(long x, long y) { throw new UnsupportedOperationException(); }
}

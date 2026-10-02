/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

final class RuntimeSupport {
    /** System property; set to {@code false} to force the Unsafe-free backend on JDK &lt; 25. */
    static final String USE_UNSAFE_PROPERTY = "net.openhft.hashing.useUnsafe";

    private static final int JAVA_FEATURE = detectJavaFeature();
    private static final boolean USE_UNSAFE =
        JAVA_FEATURE < 25 && !"false".equalsIgnoreCase(System.getProperty(USE_UNSAFE_PROPERTY));

    private RuntimeSupport() {}

    static int javaFeature() {
        return JAVA_FEATURE;
    }

    static boolean useUnsafeAccess() {
        return USE_UNSAFE;
    }

    static boolean isAtLeast(final int feature) {
        return JAVA_FEATURE >= feature;
    }

    static int parseJavaFeature(final String specificationVersion) {
        final int dot = specificationVersion.indexOf('.');
        if (dot < 0) {
            return Integer.parseInt(specificationVersion);
        }
        return Integer.parseInt(specificationVersion.substring(dot + 1));
    }

    private static int detectJavaFeature() {
        try {
            final Object version = Runtime.class.getMethod("version").invoke(Runtime.getRuntime());
            return (Integer) version.getClass().getMethod("feature").invoke(version);
        } catch (final Throwable ignore) {
            return parseJavaFeature(System.getProperty("java.specification.version", "8"));
        }
    }
}

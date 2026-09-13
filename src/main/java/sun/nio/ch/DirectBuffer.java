/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package sun.nio.ch;

/**
 * Stub for JDK internal class sun.nio.ch.DirectBuffer.
 * <p>
 * - When cross compiling for Java SE 7 and 8, this stub class bypasses compiler sun-api
 *   warnings.
 * - When cross compiling for Java SE 9+, the package 'sun.nio.ch' is not exported from
 *   'java.base'. This stub class helps to access the class at compile time without
 *   '--add-exports' arguments and bypasses sun-api warnings.
 * - Only used methods are declared.
 * - In test and production runtime, the real class is loaded from the boot class path.
 */
public interface DirectBuffer {
    long address();
}

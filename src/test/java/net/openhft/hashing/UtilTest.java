/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UtilTest {

    @Test
    void testStringHash() {
        // This is a sentinel test to make sure that in all known VMs it will not fall back to use
        // native CharSequenceAccess
        assertNotSame(Util.VALID_STRING_HASH, UnknownJvmStringHash.INSTANCE);
    }
}

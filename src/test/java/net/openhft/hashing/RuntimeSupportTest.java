/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class RuntimeSupportTest {
    @Test
    public void parsesJavaFeatureVersions() {
        assertEquals(8, RuntimeSupport.parseJavaFeature("1.8"));
        assertEquals(11, RuntimeSupport.parseJavaFeature("11"));
        assertEquals(25, RuntimeSupport.parseJavaFeature("25"));
    }
}

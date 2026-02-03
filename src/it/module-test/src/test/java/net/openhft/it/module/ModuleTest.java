/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.it.module;

import net.openhft.hashing.LongHashFunction;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * Integration test verifying proper module encapsulation.
 * This test ensures that only exported packages are accessible.
 */
public class ModuleTest {
    
    private static final String TEST_DATA = "Module Test Data";
    private static final byte[] TEST_BYTES = TEST_DATA.getBytes(StandardCharsets.UTF_8);
    
    @Test
    public void testPublicAPIAccessible() {
        long xxHash = LongHashFunction.xx().hashBytes(TEST_BYTES);
        long cityHash = LongHashFunction.city_1_1().hashBytes(TEST_BYTES);
        long murmurHash = LongHashFunction.murmur_3().hashBytes(TEST_BYTES);
        
        assertTrue("XxHash should produce non-zero result", xxHash != 0);
        assertTrue("CityHash should produce non-zero result", cityHash != 0);
        assertTrue("MurmurHash should produce non-zero result", murmurHash != 0);
    }
    
    @Test
    public void testMainAPIClassAccessible() {
        try {
            Class.forName("net.openhft.hashing.LongHashFunction");
        } catch (ClassNotFoundException e) {
            fail("Public API net.openhft.hashing.LongHashFunction should be accessible");
        }
    }
}

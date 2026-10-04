/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.it;

import net.openhft.hashing.LongHashFunction;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.*;

/**
 * Integration test demonstrating usage of Zero-Allocation-Hashing library.
 */
public class HashingTest {
    
    private static final String TEST_STRING = "Hello, World!";
    private static final byte[] TEST_BYTES = TEST_STRING.getBytes(StandardCharsets.UTF_8);
    
    @Test
    public void testXxHash() {
        LongHashFunction xxHash = LongHashFunction.xx();
        ByteBuffer buffer = ByteBuffer.wrap(TEST_BYTES);
        
        long hashFromBytes = xxHash.hashBytes(TEST_BYTES);
        long hashFromBuffer = xxHash.hashBytes(buffer);
        buffer.rewind();
        long hashFromChars = xxHash.hashChars(TEST_STRING);
        
        assertEquals("XxHash: byte[] and ByteBuffer hashes should match", hashFromBytes, hashFromBuffer);
        assertTrue("XxHash from bytes should be non-zero", hashFromBytes != 0);
        assertTrue("XxHash from chars should be non-zero", hashFromChars != 0);
    }
    
    @Test
    public void testCityHash() {
        LongHashFunction cityHash = LongHashFunction.city_1_1();
        ByteBuffer buffer = ByteBuffer.wrap(TEST_BYTES);
        
        long hashFromBytes = cityHash.hashBytes(TEST_BYTES);
        long hashFromBuffer = cityHash.hashBytes(buffer);
        buffer.rewind();
        long hashFromChars = cityHash.hashChars(TEST_STRING);
        
        assertEquals("CityHash: byte[] and ByteBuffer hashes should match", hashFromBytes, hashFromBuffer);
        assertTrue("CityHash from bytes should be non-zero", hashFromBytes != 0);
        assertTrue("CityHash from chars should be non-zero", hashFromChars != 0);
    }
    
    @Test
    public void testMurmurHash() {
        LongHashFunction murmur = LongHashFunction.murmur_3();
        ByteBuffer buffer = ByteBuffer.wrap(TEST_BYTES);
        
        long hashFromBytes = murmur.hashBytes(TEST_BYTES);
        long hashFromBuffer = murmur.hashBytes(buffer);
        buffer.rewind();
        long hashFromChars = murmur.hashChars(TEST_STRING);
        
        assertEquals("MurmurHash3: byte[] and ByteBuffer hashes should match", hashFromBytes, hashFromBuffer);
        assertTrue("MurmurHash3 from bytes should be non-zero", hashFromBytes != 0);
        assertTrue("MurmurHash3 from chars should be non-zero", hashFromChars != 0);
    }
    
    @Test
    public void testFarmHash() {
        LongHashFunction farmHash = LongHashFunction.farmUo();
        ByteBuffer buffer = ByteBuffer.wrap(TEST_BYTES);
        
        long hashFromBytes = farmHash.hashBytes(TEST_BYTES);
        long hashFromBuffer = farmHash.hashBytes(buffer);
        buffer.rewind();
        long hashFromChars = farmHash.hashChars(TEST_STRING);
        
        assertEquals("FarmHash: byte[] and ByteBuffer hashes should match", hashFromBytes, hashFromBuffer);
        assertTrue("FarmHash from bytes should be non-zero", hashFromBytes != 0);
        assertTrue("FarmHash from chars should be non-zero", hashFromChars != 0);
    }
    
    @Test
    public void testPublicAPIAccessible() {
        try {
            Class.forName("net.openhft.hashing.LongHashFunction");
        } catch (ClassNotFoundException e) {
            fail("Public API net.openhft.hashing.LongHashFunction should be accessible");
        }
    }
}

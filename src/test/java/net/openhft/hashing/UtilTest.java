package net.openhft.hashing;

import org.junit.Test;

import static org.junit.Assert.assertNotSame;

public class UtilTest {

    @Test
    public void testStringHash() {
        // This is a sentinel test to make sure that in all known VMs it will not fall back to use
        // native CharSequenceAccess
        assertNotSame(Util.VALID_STRING_HASH, UnknownJvmStringHash.INSTANCE);
    }
}

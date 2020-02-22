/*
 * Copyright 2014 Higher Frequency Trading http://www.higherfrequencytrading.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openhft.hashing;


import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import org.junit.Test;

import java.util.Arrays;
import java.util.Random;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MurmurHash3Test {

    @Test
    public void testMurmurWithoutSeed() {
        testMurmur(LongTupleHashFunction.murmur_3(), Hashing.murmur3_128());
    }

    @Test
    public void testMurmurWithSeed() {
        testMurmur(LongTupleHashFunction.murmur_3(42L), Hashing.murmur3_128(42));
    }

    private void testMurmur(LongTupleHashFunction tested, HashFunction referenceFromGuava) {
        byte[] testData = new byte[1024];
        for (int i = 0; i < testData.length; i++) {
            testData[i] = (byte) i;
        }
        for (int i = 0; i < testData.length; i++) {
            byte[] data = Arrays.copyOf(testData, i);
            byte[] ehBytes = referenceFromGuava.hashBytes(data).asBytes();
            long[] eh = new long[(ehBytes.length + 7) / 8];
            ByteBuffer.wrap(ehBytes).order(ByteOrder.LITTLE_ENDIAN).asLongBuffer().get(eh);
            LongTupleHashFunctionTest.test(tested, data, eh);
        }
    }
}

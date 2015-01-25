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
import java.util.concurrent.ThreadLocalRandom;

public class MurmurHash3Test {

    @Test
    public void testMurmurWithoutSeed() {
        testMurmur(LongHashFunction.murmur_3(), Hashing.murmur3_128());
    }

    @Test
    public void testMurmurWithSeed() {
        testMurmur(LongHashFunction.murmur_3(42L), Hashing.murmur3_128(42));
    }

    private void testMurmur(LongHashFunction tested, HashFunction referenceFromGuava) {
        byte[] testData = new byte[1024];
        ThreadLocalRandom.current().nextBytes(testData);
        for (int i = 0; i < testData.length; i++) {
            byte[] data = Arrays.copyOf(testData, i);
            LongHashFunctionTest.test(tested, data, referenceFromGuava.hashBytes(data).asLong());
        }
    }
}

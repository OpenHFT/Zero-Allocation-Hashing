/*
 * Copyright 2015 Higher Frequency Trading http://www.higherfrequencytrading.com
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

import org.junit.Test;

/**
 * This tests coherence of supporting functions like hashInt(), hashLong(), hashChars etc.
 * Algorithm is tested in OriginalFarmHashTest
 */
public class FarmHashTest {

    @Test
    public void testUo() {
        for (int len = 0; len < 1026; len++) {
            byte[] data = new byte[len];
            for (int i = 0; i < len; i++) {
                data[i] = (byte) i;
            }
            LongHashFunction f = LongHashFunction.farmUo();
            LongHashFunctionTest.test(f, data, f.hashBytes(data));

            f = LongHashFunction.farmUo(42);
            LongHashFunctionTest.test(f, data, f.hashBytes(data));

            f = LongHashFunction.farmUo(42, 123);
            LongHashFunctionTest.test(f, data, f.hashBytes(data));
        }
    }

    @Test
    public void testNa() {
        for (int len = 0; len < 1026; len++) {
            byte[] data = new byte[len];
            for (int i = 0; i < len; i++) {
                data[i] = (byte) i;
            }
            LongHashFunction f = LongHashFunction.farmNa();
            LongHashFunctionTest.test(f, data, f.hashBytes(data));

            f = LongHashFunction.farmNa(42);
            LongHashFunctionTest.test(f, data, f.hashBytes(data));

            f = LongHashFunction.farmNa(42, 123);
            LongHashFunctionTest.test(f, data, f.hashBytes(data));
        }
    }

}

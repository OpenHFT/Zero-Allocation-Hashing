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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.Assert.assertEquals;

public class XxHashCollisionTest {

    @Test
    public void xxHashCollisionTest() {
        ByteBuffer sequence = ByteBuffer.allocate(128);
        sequence.order(ByteOrder.LITTLE_ENDIAN);
        sequence.putLong(0, 1);
        sequence.putLong(16, 42);
        sequence.putLong(32, 2);
        long h1 = LongHashFunction.xx().hashBytes(sequence);

        sequence.putLong(0, 1 + 0xBA79078168D4BAFL);
        sequence.putLong(32, 2 + 0x9C90005B80000000L);
        long h2 = LongHashFunction.xx().hashBytes(sequence);
        assertEquals(h1, h2);

        sequence.putLong(0, 1 + 0xBA79078168D4BAFL * 2);
        sequence.putLong(32, 2 + 0x9C90005B80000000L * 2);

        long h3 = LongHashFunction.xx().hashBytes(sequence);
        assertEquals(h2, h3);
    }
}

/*
 * Copyright 2014-2026 chronicle.software
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import net.openhft.hashing.LongHashFunction;

import java.util.Arrays;

/** Compiled against 0.7, then executed unchanged against the candidate JAR. */
public final class LegacyAliasConsumer {
    private LegacyAliasConsumer() {
    }

    public static void main(String[] args) throws ReflectiveOperationException {
        if (args.length != 1 || !("seeded".equals(args[0]) || "unseeded".equals(args[0])))
            throw new IllegalArgumentException("Expected seeded or unseeded");
        boolean seeded = "seeded".equals(args[0]);
        long seed = 0x0123456789abcdefL;
        // These two invokestatic descriptors must link without recompiling this class.
        LongHashFunction legacy = seeded ? LongHashFunction.xx_r39(seed) : LongHashFunction.xx_r39();
        // Reflection keeps the modern name out of the 0.7 compile-time API requirement.
        LongHashFunction modern = (LongHashFunction) (seeded
                ? LongHashFunction.class.getMethod("xx", long.class).invoke(null, seed)
                : LongHashFunction.class.getMethod("xx").invoke(null));
        byte[] input = new byte[] {0, 1, -1, 7, 12, 18, 42, 64, 127, -128, 3, 5, 9, 11, 13, 15, 17};
        for (int length : new int[] {0, 1, 8, 16, 17}) {
            byte[] bytes = Arrays.copyOf(input, length);
            if (legacy.hashBytes(bytes) != modern.hashBytes(bytes))
                throw new AssertionError(args[0] + " differs from xx for length " + length);
        }
        System.out.println("PASS " + args[0] + ": linked legacy descriptor; five inputs agree with xx");
    }
}

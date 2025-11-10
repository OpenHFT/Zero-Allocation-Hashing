//
// Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
//

package net.openhft.hashing;

import javax.annotation.ParametersAreNonnullByDefault;

@ParametersAreNonnullByDefault
interface StringHash {
    long longHash(String s, LongHashFunction hashFunction, int off, int len);
    void hash(String s, LongTupleHashFunction hashFunction, int off, int len, long[] result);
}

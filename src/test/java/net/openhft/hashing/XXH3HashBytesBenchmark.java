/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Reproduces issue #101 for XXH3 hashing of a 128 byte array.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(
        value = 5,
        warmups = 3,
        jvmArgs = {
                "-XX:-TieredCompilation",
                "-XX:+UseParallelGC",
                "-Xms16g",
                "-Xmx16g",
        })
public class XXH3HashBytesBenchmark {
    private static final int INPUT_LENGTH_BYTES = 128;
    private static final LongHashFunction XXH3_64_HASH_FUNCTION = LongHashFunction.xx3();
    private static final byte[] ZERO_FILLED_128_BYTE_INPUT = new byte[INPUT_LENGTH_BYTES];

    @Benchmark
    public long hashZeroFilledByteArray128Bytes() {
        return XXH3_64_HASH_FUNCTION.hashBytes(ZERO_FILLED_128_BYTE_INPUT);
    }

    public static void main(String[] args) throws IOException {
        org.openjdk.jmh.Main.main(args);
    }
}

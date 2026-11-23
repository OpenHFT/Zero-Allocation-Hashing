/*
 * Copyright 2013-2025 chronicle.software; SPDX-License-Identifier: Apache-2.0
 */
package net.openhft.hashing;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.util.Random;
import java.util.concurrent.TimeUnit;

/** Steady-state hashing of a fixed-seed byte array. */
@State(Scope.Thread)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(3)
public class LongHashFunctionBenchmark {
    @Param("8192")
    public int inputBytes;

    private byte[] data;

    @Setup
    public void prepareInput() {
        data = new byte[inputBytes];
        new Random(79L).nextBytes(data);
    }

    @Benchmark
    public long xx() {
        return LongHashFunction.xx().hashBytes(data);
    }

    @Benchmark
    public long xx3() {
        return LongHashFunction.xx3().hashBytes(data);
    }

    @Benchmark
    public long xx128low() {
        return LongHashFunction.xx128low().hashBytes(data);
    }

    @Benchmark
    public long murmur_3() {
        return LongHashFunction.murmur_3().hashBytes(data);
    }

    @Benchmark
    public long metro() {
        return LongHashFunction.metro().hashBytes(data);
    }

    @Benchmark
    public long city_1_1() {
        return LongHashFunction.city_1_1().hashBytes(data);
    }

    @Benchmark
    public long farmNa() {
        return LongHashFunction.farmNa().hashBytes(data);
    }

    @Benchmark
    public long farmUo() {
        return LongHashFunction.farmUo().hashBytes(data);
    }

    @Benchmark
    public long wy_3() {
        return LongHashFunction.wy_3().hashBytes(data);
    }
}

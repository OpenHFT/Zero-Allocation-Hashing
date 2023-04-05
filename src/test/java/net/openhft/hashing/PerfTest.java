/*
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

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 3, time = 3, timeUnit = TimeUnit.SECONDS)
public class PerfTest {

    @State(Scope.Benchmark)
    static public class HashState {
        byte[] data;

        @Setup(Level.Iteration)
        public void setUp()  {
            data = new byte[8192];
            ThreadLocalRandom.current().nextBytes(data);
        }
    }

    /**
     * <p>LongHashFunction.xx()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmarkXxHash(HashState state)
    {
        return LongHashFunction.xx().hashBytes(state.data);
    }

    /**
     * <p>LongHashFunction.xx3()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmarkXXH3(HashState state)
    {
        return LongHashFunction.xx3().hashBytes(state.data);
    }

    /**
     * <p>LongHashFunction.xx128low()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmarkXXH128(HashState state)
    {
        return LongHashFunction.xx128low().hashBytes(state.data);
    }

    /**
     * <p>LongHashFunction.murmur_3()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmarkMurmurHash_3(HashState state)
    {
        return LongHashFunction.murmur_3().hashBytes(state.data);
    }

    /**
     * <p>LongHashFunction.metro()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmarkMetroHash(HashState state)
    {
        return LongHashFunction.metro().hashBytes(state.data);
    }

    /**
     * <p>LongHashFunction.city_1_1()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmarkCity_1_1(HashState state)
    {
        return LongHashFunction.city_1_1().hashBytes(state.data);
    }

    /**
     * <p>LongHashFunction.farmNa()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmarkFarmNa(HashState state)
    {
        return LongHashFunction.farmNa().hashBytes(state.data);
    }

    /**
     * <p>LongHashFunction.farmUo()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmarkFarmUo(HashState state)
    {
        return LongHashFunction.farmUo().hashBytes(state.data);
    }

    /**
     * <p>LongHashFunction.wy_3()</p>
     *
     * @param state a {@link PerfTest.HashState} object.
     * @return the computed hash
     */
    @Benchmark
    public long benchmark_wy_3(HashState state)
    {
        return LongHashFunction.wy_3().hashBytes(state.data);
    }

    /*
     * <p>main.</p>
     *
     * @param args a {@link java.lang.String} object.
     * @throws org.openjdk.jmh.runner.RunnerException if any.
     */
    public static void main( String... args )
        throws RunnerException
    {
        Options opts = new OptionsBuilder()
            .measurementIterations( 3 )
            .measurementTime( TimeValue.milliseconds( 3000 ) )
            .forks( 1 )
            .build();
        new Runner( opts ).run();
    }
}

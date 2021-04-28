// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Exporters;

namespace Microsoft.Data.SqlClient.Benchmark.CLI
{
    public static class BenchmarkConfig
    {
        public static readonly ManualConfig Instance = DefaultConfig.Instance
            .AddJob(Job.Default.WithLaunchCount(1).WithIterationCount(5).WithWarmupCount(0))
            .AddDiagnoser(MemoryDiagnoser.Default)
            .AddDiagnoser(ThreadingDiagnoser.Default)
            .AddExporter(MarkdownExporter.GitHub)
            .WithOption(ConfigOptions.DisableOptimizationsValidator, true)
        ;
    }
}

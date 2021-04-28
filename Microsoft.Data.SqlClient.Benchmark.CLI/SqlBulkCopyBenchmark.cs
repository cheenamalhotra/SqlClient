// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Dapper;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClient.Benchmark.CLI
{
    public static class SqlBulkCopyBenchmark
    {
        private const string _database = "SqlBulkCopyBenchmark";
        private const int _count = (int)1e5;
        private const int _iterationCount = 20;

        private static readonly IEnumerable<ItemToCopy> _items;
        private static readonly IDataReader _reader;

        private static readonly string _connString = new SqlConnectionStringBuilder()
        {
            DataSource = "localhost",
            InitialCatalog = _database,
            IntegratedSecurity = true,
            MultipleActiveResultSets = true
        }.ToString();

        static SqlBulkCopyBenchmark()
        {
            var item = new ItemToCopy();

            using var cmaster = new SqlConnection(new SqlConnectionStringBuilder(_connString) { InitialCatalog = "master" }.ToString());
            cmaster.Open();

            cmaster.Execute($@"
                ALTER DATABASE [{_database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE;

                DROP DATABASE IF EXISTS [{_database}];

                CREATE DATABASE [{_database}];
            ");

            using var c = new SqlConnection(_connString);

            c.Execute(ItemToCopy.TableSql);
            c.Execute(ItemToCopy.SrcTableSql);
            c.Execute(ItemToCopy.TargetTableSql);

            _items = Enumerable.Range(0, _count).Select(x => item).ToArray();

            _reader = ItemToCopy.CreateReader(_items, ItemToCopy.TableName);

            // Populate source table
            for (int i = 0; i < _iterationCount; i++)
            {
                using (var bc = new SqlBulkCopy(_connString, SqlBulkCopyOptions.TableLock))
                {
                    bc.BatchSize = _count;
                    bc.DestinationTableName = ItemToCopy.Source_TableName;
                    bc.BulkCopyTimeout = 60;

                    bc.WriteToServer(_reader);
                }
            }
        }

        public static void RunBenchmark()
        {
            BenchmarkRunner.Run<IDataReaderBenchmark>(BenchmarkConfig.Instance);
            BenchmarkRunner.Run<SqlDataReaderBenchmark>(BenchmarkConfig.Instance);
        }

        public class IDataReaderBenchmark
        {
            [Benchmark]
            public void BulkCopy()
            {
                for (int i = 1; i <= _iterationCount; i++)
                {
                    Console.WriteLine($"{DateTime.Now} - Iteration #{i}");
                    _reader.Close(); // this resets the reader

                    using var bc = new SqlBulkCopy(_connString, SqlBulkCopyOptions.TableLock);
                    bc.BatchSize = _count;
                    bc.DestinationTableName = ItemToCopy.TableName;
                    bc.BulkCopyTimeout = 60;

                    bc.WriteToServer(_reader);
                }

                Console.WriteLine($"{DateTime.Now} - Finished");
            }

            [Benchmark]
            public async Task BulkCopyAsync()
            {
                for (int i = 1; i <= _iterationCount; i++)
                {
                    Console.WriteLine($"{DateTime.Now} - Iteration #{i}");
                    _reader.Close(); // this resets the reader

                    using var bc = new SqlBulkCopy(_connString, SqlBulkCopyOptions.TableLock);
                    bc.BatchSize = _count;
                    bc.DestinationTableName = ItemToCopy.TableName;
                    bc.BulkCopyTimeout = 60;

                    await bc.WriteToServerAsync(_reader);
                }

                Console.WriteLine($"{DateTime.Now} - Finished");
            }
        }

        public class SqlDataReaderBenchmark : IDisposable
        {
            private SqlConnection _sqlConnection;
            private SqlDataReader _sqlReader;

            private bool _disposedValue;

            [IterationSetup]
            public void IterationSetup()
            {
                _sqlConnection = new SqlConnection(_connString);
                _sqlConnection.Open();

                string cmdText = "";
                for (int i = 0; i < _iterationCount; i++)
                {
                    cmdText += $"SELECT * FROM {ItemToCopy.Source_TableName};";
                }

                _sqlReader = new SqlCommand(cmdText, _sqlConnection).ExecuteReader();
                Console.WriteLine($"// IterationSetup");
            }

            [Benchmark]
            public void BulkCopy()
            {
                for (int i = 1; i <= _iterationCount; i++)
                {
                    Console.WriteLine($"{DateTime.Now} - Iteration #{i}");
                    _sqlReader.NextResult();

                    using var bc = new SqlBulkCopy(_connString, SqlBulkCopyOptions.TableLock);
                    bc.BatchSize = _count;
                    bc.DestinationTableName = ItemToCopy.Target_TableName;
                    bc.BulkCopyTimeout = 60;

                    bc.WriteToServer(_sqlReader);
                }

                Console.WriteLine($"{DateTime.Now} - Finished");
            }

            [Benchmark]
            public async Task BulkCopyAsync()
            {
                for (int i = 1; i <= _iterationCount; i++)
                {
                    Console.WriteLine($"{DateTime.Now} - Iteration #{i}");
                    _sqlReader.NextResult();

                    using var bc = new SqlBulkCopy(_connString, SqlBulkCopyOptions.TableLock);
                    bc.BatchSize = _count;
                    bc.DestinationTableName = ItemToCopy.Target_TableName;
                    bc.BulkCopyTimeout = 60;

                    await bc.WriteToServerAsync(_sqlReader);
                }

                Console.WriteLine($"{DateTime.Now} - Finished");
            }

            [IterationCleanup]
            public void IterationCleanup()
            {
                Dispose();
                Console.WriteLine($"// IterationCleanup");
            }

            protected virtual void Dispose(bool disposing)
            {
                if (!_disposedValue)
                {
                    if (disposing)
                    {
                        _sqlReader.Close();
                        _sqlConnection.Dispose();
                    }

                    _disposedValue = true;
                }
            }

            public void Dispose()
            {
                // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
                Dispose(disposing: true);
                GC.SuppressFinalize(this);
            }
        }
    }
}

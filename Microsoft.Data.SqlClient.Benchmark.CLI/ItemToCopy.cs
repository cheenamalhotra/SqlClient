// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Data;

namespace Microsoft.Data.SqlClient.Benchmark.CLI
{
    public class ItemToCopy
    {
        // IDataReader Bulk Copy
        public const string TableName = "TestTable";

        // SqlDataReader Bulk Copy
        public const string Source_TableName = "TestTableSrc";
        public const string Target_TableName = "TestTableTarget";

        // keeping this data static so the performance of the benchmark is not varied by the data size & shape
        public int IntColumn { get; } = 123456;
        public bool BoolColumn { get; } = true;
        public string StringColumn { get; } = "abcdefg";
        public Guid GuidColumn { get; } = new Guid("0153B8BC-27C9-4DA7-BDE4-E56E692BECE1");
        public long LongColumn { get; } = 123456L;
        public decimal DecimalColumn { get; } = 123456.7m;
        public double DoubleColumn { get; } = 123456.7d;
        public DateTime DateTimeColumn { get; } = new DateTime(2010, 1, 1);
        public bool? NullableBoolColumn { get; }
        public int? NullableIntColumn { get; }

        public static readonly string TableSql = SqlGen(TableName);
        public static readonly string SrcTableSql = SqlGen(Source_TableName);
        public static readonly string TargetTableSql = SqlGen(Target_TableName);

        static string SqlGen(string TableName) => $@"
                CREATE TABLE {TableName} (
                      IntColumn INT NOT NULL
                    , BoolColumn BIT NOT NULL
                    , StringColumn NVARCHAR(25) NOT NULL
                    , GuidColumn UNIQUEIDENTIFIER NOT NULL
                    , LongColumn BIGINT NOT NULL
                    , DecimalColumn FLOAT NOT NULL
                    , DoubleColumn FLOAT NOT NULL
                    , DateTimeColumn DATETIME NOT NULL
                    , NullableBoolColumn BIT NULL
                    , NullableIntColumn INT NULL
                    , IntColumn2 INT NOT NULL
                    , BoolColumn2 BIT NOT NULL
                    , StringColumn2 NVARCHAR(25) NOT NULL
                    , GuidColumn2 UNIQUEIDENTIFIER NOT NULL
                    , LongColumn2 BIGINT NOT NULL
                    , DecimalColumn2 FLOAT NOT NULL
                    , DoubleColumn2 FLOAT NOT NULL
                    , DateTimeColumn2 DATETIME NOT NULL
                    , NullableBoolColumn2 BIT NULL
                    , NullableIntColumn2 INT NULL
                    , Int2Column INT NOT NULL
                    , Int3Column INT NOT NULL
                    , Int4Column INT NOT NULL
                    , Int5Column INT NOT NULL
                    , Int6Column INT NOT NULL
                    , Int7Column INT NOT NULL
                    , Int8Column INT NOT NULL
                    , Int9Column INT NOT NULL
                    , Int10Column INT NOT NULL
                    , Bool2Column BIT NOT NULL
                    , Bool3Column BIT NOT NULL
                    , Bool4Column BIT NOT NULL
                    , Bool5Column BIT NOT NULL
                    , Bool6Column BIT NOT NULL
                    , Bool7Column BIT NOT NULL
                    , Bool8Column BIT NOT NULL
                    , Bool9Column BIT NOT NULL
                    , Bool10Column BIT NOT NULL
                    , Decimal2Column FLOAT NOT NULL
                    , Decimal3Column FLOAT NOT NULL
                    , Decimal4Column FLOAT NOT NULL
                    , Decimal5Column FLOAT NOT NULL
                    , Decimal6Column FLOAT NOT NULL
                    , Decimal7Column FLOAT NOT NULL
                    , Decimal8Column FLOAT NOT NULL
                    , Decimal9Column FLOAT NOT NULL
                    , Decimal10Column FLOAT NOT NULL
                )
        ";

        public static IDataReader CreateReader(IEnumerable<ItemToCopy> items, string TableName) => new EnumerableDataReaderFactoryBuilder<ItemToCopy>(TableName)
                .Add("IntColumn", i => i.IntColumn)
                .Add("BoolColumn", i => i.BoolColumn)
                .Add("StringColumn", i => i.StringColumn)
                .Add("GuidColumn", i => i.GuidColumn)
                .Add("LongColumn", i => i.LongColumn)
                .Add("DecimalColumn", i => i.DecimalColumn)
                .Add("DoubleColumn", i => i.DoubleColumn)
                .Add("DateTimeColumn", i => i.DateTimeColumn)
                .Add("NullableBoolColumn", i => i.NullableBoolColumn)
                .Add("NullableIntColumn", i => i.NullableIntColumn)
                .Add("IntColumn2", i => i.IntColumn)
                .Add("BoolColumn2", i => i.BoolColumn)
                .Add("StringColumn2", i => i.StringColumn)
                .Add("GuidColumn2", i => i.GuidColumn)
                .Add("LongColumn2", i => i.LongColumn)
                .Add("DecimalColumn2", i => i.DecimalColumn)
                .Add("DoubleColumn2", i => i.DoubleColumn)
                .Add("DateTimeColumn2", i => i.DateTimeColumn)
                .Add("NullableBoolColumn2", i => i.NullableBoolColumn)
                .Add("NullableIntColumn2", i => i.NullableIntColumn)
                .Add("Int2Column", i => i.IntColumn)
                .Add("Int3Column", i => i.IntColumn)
                .Add("Int4Column", i => i.IntColumn)
                .Add("Int5Column", i => i.IntColumn)
                .Add("Int6Column", i => i.IntColumn)
                .Add("Int7Column", i => i.IntColumn)
                .Add("Int8Column", i => i.IntColumn)
                .Add("Int9Column", i => i.IntColumn)
                .Add("Int10Column", i => i.IntColumn)
                .Add("Bool2Column", i => i.BoolColumn)
                .Add("Bool3Column", i => i.BoolColumn)
                .Add("Bool4Column", i => i.BoolColumn)
                .Add("Bool5Column", i => i.BoolColumn)
                .Add("Bool6Column", i => i.BoolColumn)
                .Add("Bool7Column", i => i.BoolColumn)
                .Add("Bool8Column", i => i.BoolColumn)
                .Add("Bool9Column", i => i.BoolColumn)
                .Add("Bool10Column", i => i.BoolColumn)
                .Add("Decimal2Column", i => i.DecimalColumn)
                .Add("Decimal3Column", i => i.DecimalColumn)
                .Add("Decimal4Column", i => i.DecimalColumn)
                .Add("Decimal5Column", i => i.DecimalColumn)
                .Add("Decimal6Column", i => i.DecimalColumn)
                .Add("Decimal7Column", i => i.DecimalColumn)
                .Add("Decimal8Column", i => i.DecimalColumn)
                .Add("Decimal9Column", i => i.DecimalColumn)
                .Add("Decimal10Column", i => i.DecimalColumn)
                .BuildFactory()
                .CreateReader(items)
            ;
    }
}

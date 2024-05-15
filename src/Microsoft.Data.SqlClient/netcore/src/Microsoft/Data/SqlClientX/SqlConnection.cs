using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Common;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;

namespace Microsoft.Data.SqlClientX
{
    internal class SqlConnection : DbConnection
    {
        public override string ConnectionString { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public override string Database => throw new NotImplementedException();

        public override string DataSource => throw new NotImplementedException();

        public override string ServerVersion => throw new NotImplementedException();

        public override ConnectionState State => throw new NotImplementedException();

        public override void Open()
        {
            OpenAsync().GetAwaiter().GetResult();
        }

        public new async Task OpenAsync()
        {
            await CloseAsync();
            throw new NotImplementedException();
        }

        public override void Close()
        {
            throw new NotImplementedException();
        }

        public new Task CloseAsync()
        {
            throw new NotImplementedException();
        }

        protected override DbTransaction BeginDbTransaction(IsolationLevel isolationLevel)
        {
            throw new NotImplementedException();
        }

        protected Task<DbTransaction> BeginDbTransactionAsync(IsolationLevel isolationLevel)
        {
            throw new NotImplementedException();
        }

        protected override DbCommand CreateDbCommand()
        {
            throw new NotImplementedException();
        }

        protected Task<DbCommand> CreateDbCommandAsync()
        {
            throw new NotImplementedException();
        }

        public override void ChangeDatabase(string databaseName)
        {
            throw new NotImplementedException();
        }

        public Task ChangeDatabaseAsync(string databaseName)
        {
            throw new NotImplementedException();
        }
    }

    internal delegate Func<SqlAuthenticationParameters, CancellationToken, Task<SqlAuthenticationToken>> AccessTokenCallback();
}

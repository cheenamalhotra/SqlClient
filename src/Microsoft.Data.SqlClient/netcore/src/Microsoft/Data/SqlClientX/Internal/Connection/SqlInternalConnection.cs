using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Transactions;
using Microsoft.Data.ProviderBase;
using Microsoft.Data.SqlClientX.TDS;

namespace Microsoft.Data.SqlClientX.Internal.Connection
{
    internal class SqlInternalConnection: DbConnectionInternal, IDisposable
    {
        public SqlInternalConnection(SqlConnectionString connectionOptions): base(connectionOptions) { }

        public TDSExecutor TdsExeecutor { get; set; }

        public override string ServerVersion => throw new NotImplementedException();

        internal SqlConnectionStateInfo ConnectionStateInfo { get; set; }

        protected override void Activate(Transaction transaction)
        {
            throw new NotImplementedException();
        }

        protected override void Deactivate()
        {
            throw new NotImplementedException();
        }
        public override DbTransaction BeginTransaction(System.Data.IsolationLevel il)
        {
            throw new NotImplementedException();
        }

        public override void EnlistTransaction(Transaction transaction)
        {
            throw new NotImplementedException();
        }
    }
}

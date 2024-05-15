using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Data.SqlClientX.Net;
using Microsoft.Data.SqlClientX.Net.Types;

namespace Microsoft.Data.SqlClientX.TDS
{
    /// <summary>
    /// Called by a SqlCommand to perform operations on SQL connection.
    /// </summary>
    internal class CommandExecutor
    {
        // Command Handler
        // OLD: TdsExecuteSQLBatch
        public async Task ExecuteSQLBatchAsync(Messenger messenger)
        {
            // instantiate all handlers
            // execute read/write on TDS Executor
        }

        public async Task ExecuteRPCAsync()
        {

        }

        public async Task ExecuteTransactionManagerRequestAsync()
        {

        }

        public Task<Packet> ReadPacketAsync()
        {

        }
    }
}

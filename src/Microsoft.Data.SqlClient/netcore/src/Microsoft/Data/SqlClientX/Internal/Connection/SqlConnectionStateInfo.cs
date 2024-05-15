using System;
using Microsoft.Data.ProviderBase;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClientX.Net;

namespace Microsoft.Data.SqlClientX.Internal.Connection
{
    internal class SqlConnectionStateInfo
    {
        internal string RoutingDestination { get; }

        internal TimeoutTimer TimeoutTimer { get; }

        internal bool IsMarsEnabled { get; }

        internal bool IsSQLDNSCachingSupported { get; set; }

        internal bool IsFedAuthRequired { get; set; }

        internal Guid ClientConnectionId { get; }

        internal Guid OriginalClientConnectionId { get; }

        internal SqlDnsInfo SqlDnsInfo { get; set; }

        internal SqlConnectionPoolGroupProviderInfo PoolGroupProviderInfo { get; set; }

        internal SqlConnectionString ConnectionOptions { get; }

        // The pool that this connection is associated with, if at all it is.
        internal DbConnectionPool DbConnectionPool { get; set; }

        internal Messenger Messenger { get; set; }

        // This is used to preserve the authentication context object if we decide to cache it for subsequent connections in the same pool.
        // This will finally end up in _dbConnectionPool.AuthenticationContexts, but only after 1 successful login to SQL Server using this context.
        // This variable is to persist the context after we have generated it, but before we have successfully completed the login with this new context.
        // If this connection attempt ended up re-using the existing context and not create a new one, this will be null (since the context is not new).
        internal DbConnectionPoolAuthenticationContext NewDbConnectionPoolAuthenticationContext { get; set; }

        // The key of the authentication context, built from information found in the FedAuthInfoToken.
        internal DbConnectionPoolAuthenticationContextKey DbConnectionPoolAuthenticationContextKey { get; set; }

        // Connection Resiliency
        internal bool SessionRecoveryRequested { get; set; }

        internal bool SessionRecoveryAcknowledged { get; set; }

        // internal for use from TdsParser only, other should use CurrentSessionData property that will fix database and language
        internal SqlConnSessionData CurrentSessionData { get; set; }

        internal SqlConnSessionData RecoverySessionData { get; set; }

        internal void StartPhase(SqlConnectionTimeoutErrorPhase phase)
        {

        }

        internal void EndPhase(SqlConnectionTimeoutErrorPhase phase)
        {

        }

        public SqlConnectionStateInfo() { }

    }
}

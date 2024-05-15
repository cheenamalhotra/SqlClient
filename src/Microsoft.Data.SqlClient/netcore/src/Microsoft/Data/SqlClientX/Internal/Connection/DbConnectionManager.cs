using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.ProviderBase;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClientX.TDS;

namespace Microsoft.Data.SqlClientX.Internal.Connection
{
    internal class DbConnectionManager
    {
        public DbConnectionManager() { }

        public static async Task<SqlInternalConnection> GetConnectionAsync(
            DbConnectionPoolIdentity identity,
            SqlConnectionString connectionOptions,
            SqlCredential credential,
            object providerInfo,
            string newPassword,
            SecureString newSecurePassword,
            bool redirectedUserInstance,
            SqlConnectionString userConnectionOptions = null, // NOTE: userConnectionOptions may be different to connectionOptions if the connection string has been expanded (see SqlConnectionString.Expand)
            SessionData reconnectSessionData = null,
            bool applyTransientFaultHandling = false,
            string accessToken = null,
            DbConnectionPool pool = null,
            AccessTokenCallback accessTokenCallback = null)
        {
            SqlInternalConnection connection;
            SqlConnectionStateInfo stateInfo = new();
            stateInfo.DbConnectionPool = pool;

            if (connectionOptions.ConnectRetryCount > 0)
            {
                stateInfo.RecoverySessionData = reconnectSessionData;
                if (reconnectSessionData == null)
                {
                    stateInfo.CurrentSessionData = new SqlConnSessionData();
                }
                else
                {
                    stateInfo.CurrentSessionData = new SqlConnSessionData(stateInfo.RecoverySessionData);
                    _originalDatabase = stateInfo.RecoverySessionData._initialDatabase;
                    _originalLanguage = stateInfo.RecoverySessionData._initialLanguage;
                }
            }

            if (accessToken != null)
            {
                _accessTokenInBytes = Encoding.Unicode.GetBytes(accessToken);
            }

            _accessTokenCallback = accessTokenCallback;

            _activeDirectoryAuthTimeoutRetryHelper = new ActiveDirectoryAuthenticationTimeoutRetryHelper();
            _sqlAuthenticationProviderManager = SqlAuthenticationProviderManager.Instance;

            _identity = identity;
            Debug.Assert(newSecurePassword != null || newPassword != null, "cannot have both new secure change password and string based change password to be null");
            Debug.Assert(credential == null || (string.IsNullOrEmpty(connectionOptions.UserID) && string.IsNullOrEmpty(connectionOptions.Password)), "cannot mix the new secure password system and the connection string based password");

            Debug.Assert(credential == null || !connectionOptions.IntegratedSecurity, "Cannot use SqlCredential and Integrated Security");

            stateInfo.PoolGroupProviderInfo = (SqlConnectionPoolGroupProviderInfo)providerInfo;
            _fResetConnection = connectionOptions.ConnectionReset;
            if (_fResetConnection && _recoverySessionData == null)
            {
                _originalDatabase = connectionOptions.InitialCatalog;
                _originalLanguage = connectionOptions.CurrentLanguage;
            }

            _timeoutErrorInternal = new SqlConnectionTimeoutErrorInternal();
            _credential = credential;

            _parserLock.Wait(canReleaseFromAnyThread: false);
            ThreadHasParserLockForClose = true;   // In case of error, let ourselves know that we already own the parser lock

            try
            {
                _timeout = TimeoutTimer.StartSecondsTimeout(connectionOptions.ConnectTimeout);

                // If transient fault handling is enabled then we can retry the login up to the ConnectRetryCount.
                int connectionEstablishCount = applyTransientFaultHandling ? connectionOptions.ConnectRetryCount + 1 : 1;
                int transientRetryIntervalInMilliSeconds = connectionOptions.ConnectRetryInterval * 1000; // Max value of transientRetryInterval is 60*1000 ms. The max value allowed for ConnectRetryInterval is 60
                for (int i = 0; i < connectionEstablishCount; i++)
                {
                    try
                    {
                        await OpenLoginEnlistAsync(connection, _timeout, connectionOptions, credential, newPassword, newSecurePassword, redirectedUserInstance);

                        break;
                    }
                    catch (SqlException sqlex)
                    {
                        if (i + 1 == connectionEstablishCount
                            || !applyTransientFaultHandling
                            || _timeout.IsExpired
                            || _timeout.MillisecondsRemaining < transientRetryIntervalInMilliSeconds
                            || !IsTransientError(sqlex))
                        {
                            throw;
                        }
                        else
                        {
                            Thread.Sleep(transientRetryIntervalInMilliSeconds);
                        }
                    }
                }
            }
            finally
            {
                ThreadHasParserLockForClose = false;
                _parserLock.Release();
            }
            connection.ConnectionStateInfo = stateInfo;
            SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.ctor|ADV> {0}, constructed new TDS internal connection", ObjectID);
            return connection;
        }

        private async Task OpenLoginEnlistAsync(TimeoutTimer timeout,
                                    SqlConnectionString connectionOptions,
                                    SqlCredential credential,
                                    string newPassword,
                                    SecureString newSecurePassword,
                                    bool redirectedUserInstance)
        {
            bool useFailoverPartner; // should we use primary or secondary first
            ServerInfo dataSource = new ServerInfo(connectionOptions);
            string failoverPartner;

            if (null != PoolGroupProviderInfo)
            {
                useFailoverPartner = PoolGroupProviderInfo.UseFailoverPartner;
                failoverPartner = PoolGroupProviderInfo.FailoverPartner;
            }
            else
            {
                // Only ChangePassword or SSE User Instance comes through this code path.
                useFailoverPartner = false;
                failoverPartner = ConnectionOptions.FailoverPartner;
            }

            _timeoutErrorInternal.SetInternalSourceType(useFailoverPartner ? SqlConnectionInternalSourceType.Failover : SqlConnectionInternalSourceType.Principle);

            bool hasFailoverPartner = !string.IsNullOrEmpty(failoverPartner);

            // Open the connection and Login
            try
            {
                _timeoutErrorInternal.SetAndBeginPhase(SqlConnectionTimeoutErrorPhase.PreLoginBegin);
                if (hasFailoverPartner)
                {
                    _timeoutErrorInternal.SetFailoverScenario(true); // this is a failover scenario
                    await LoginWithFailoverAsync(
                                useFailoverPartner,
                                dataSource,
                                failoverPartner,
                                newPassword,
                                newSecurePassword,
                                redirectedUserInstance,
                                connectionOptions,
                                credential,
                                timeout);
                }
                else
                {
                    _timeoutErrorInternal.SetFailoverScenario(false); // not a failover scenario
                    await LoginNoFailoverAsync(
                            dataSource,
                            newPassword,
                            newSecurePassword,
                            redirectedUserInstance,
                            connectionOptions,
                            credential,
                            timeout);
                }
                _timeoutErrorInternal.EndPhase(SqlConnectionTimeoutErrorPhase.PostLogin);
            }
            catch (Exception e)
            {
                if (ADP.IsCatchableExceptionType(e))
                {
                    LoginFailure();
                }
                throw;
            }
            _timeoutErrorInternal.SetAllCompleteMarker();

#if DEBUG
            _parser._physicalStateObj.InvalidateDebugOnlyCopyOfSniContext();
#endif
        }

        // Is the given Sql error one that should prevent retrying
        //   to connect.
        private bool IsDoNotRetryConnectError(SqlException exc)
        {
            return (TdsEnums.LOGON_FAILED == exc.Number) // actual logon failed, i.e. bad password
                || (TdsEnums.PASSWORD_EXPIRED == exc.Number) // actual logon failed, i.e. password isExpired
                || (TdsEnums.IMPERSONATION_FAILED == exc.Number)  // Insufficient privilege for named pipe, among others
                || exc._doNotReconnect; // Exception explicitly suppressed reconnection attempts
        }

        // Attempt to login to a host that does not have a failover partner
        //
        //  Will repeatedly attempt to connect, but back off between each attempt so as not to clog the network.
        //  Back off period increases for first few failures: 100ms, 200ms, 400ms, 800ms, then 1000ms for subsequent attempts
        //
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        //  DEVNOTE: The logic in this method is paralleled by the logic in LoginWithFailover.
        //           Changes to either one should be examined to see if they need to be reflected in the other
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        private async Task LoginNoFailoverAsync(ServerInfo serverInfo,
                                     string newPassword,
                                     SecureString newSecurePassword,
                                     bool redirectedUserInstance,
                                     SqlConnectionString connectionOptions,
                                     SqlCredential credential,
                                     TimeoutTimer timeout,
                                     bool async,
                                     CancellationToken cancellationToken)
        {
            Debug.Assert(object.ReferenceEquals(connectionOptions, this.ConnectionOptions), "ConnectionOptions argument and property must be the same"); // consider removing the argument
            int routingAttempts = 0;
            ServerInfo originalServerInfo = serverInfo; // serverInfo may end up pointing to new object due to routing, original object is used to set CurrentDatasource
            SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.LoginNoFailover|ADV> {0}, host={1}", ObjectID, serverInfo.UserServerName);
            int sleepInterval = 100;  //milliseconds to sleep (back off) between attempts.

            ResolveExtendedServerName(serverInfo, !redirectedUserInstance, connectionOptions);

            long timeoutUnitInterval = 0;

            if (connectionOptions.MultiSubnetFailover)
            {
                // Determine unit interval
                if (timeout.IsInfinite)
                {
                    timeoutUnitInterval = checked((long)(ADP.FailoverTimeoutStep * (1000L * ADP.DefaultConnectionTimeout)));
                }
                else
                {
                    timeoutUnitInterval = checked((long)(ADP.FailoverTimeoutStep * timeout.MillisecondsRemaining));
                }
            }
            // Only three ways out of this loop:
            //  1) Successfully connected
            //  2) Parser threw exception while main timer was expired
            //  3) Parser threw logon failure-related exception
            //  4) Parser threw exception in post-initial connect code,
            //      such as pre-login handshake or during actual logon. (parser state != Closed)
            //
            //  Of these methods, only #1 exits normally. This preserves the call stack on the exception
            //  back into the parser for the error cases.
            int attemptNumber = 0;
            TimeoutTimer intervalTimer = null;
            while (true)
            {
                if (connectionOptions.MultiSubnetFailover)
                {
                    attemptNumber++;
                    // Set timeout for this attempt, but don't exceed original timer
                    long nextTimeoutInterval = checked(timeoutUnitInterval * attemptNumber);
                    long milliseconds = timeout.MillisecondsRemaining;
                    if (nextTimeoutInterval > milliseconds)
                    {
                        nextTimeoutInterval = milliseconds;
                    }
                    intervalTimer = TimeoutTimer.StartMillisecondsTimeout(nextTimeoutInterval);
                }

                // Re-allocate parser each time to make sure state is known
                // RFC 50002652 - if parser was created by previous attempt, dispose it to properly close the socket, if created
                if (_parser != null)
                    _parser.Disconnect();

                _parser = new TdsParser(ConnectionOptions.MARS, ConnectionOptions.Asynchronous);
                Debug.Assert(SniContext.Undefined == Parser._physicalStateObj.SniContext, $"SniContext should be Undefined; actual Value: {Parser._physicalStateObj.SniContext}");

                try
                {
                    await AttemptOneLoginAsync(serverInfo,
                                    newPassword,
                                    newSecurePassword,
                                    connectionOptions.MultiSubnetFailover ? intervalTimer : timeout,
                                    async, cancellationToken);

                    if (connectionOptions.MultiSubnetFailover && null != ServerProvidedFailOverPartner)
                    {
                        // connection succeeded: trigger exception if server sends failover partner and MultiSubnetFailover is used
                        throw SQL.MultiSubnetFailoverWithFailoverPartner(serverProvidedFailoverPartner: true, internalConnection: this);
                    }

                    if (RoutingInfo != null)
                    {
                        SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.LoginNoFailover> Routed to {0}", serverInfo.ExtendedServerName);
                        if (routingAttempts > 0)
                        {
                            throw SQL.ROR_RecursiveRoutingNotSupported(this);
                        }

                        if (timeout.IsExpired)
                        {
                            throw SQL.ROR_TimeoutAfterRoutingInfo(this);
                        }

                        serverInfo = new ServerInfo(ConnectionOptions, RoutingInfo, serverInfo.ResolvedServerName, serverInfo.ServerSPN);
                        _timeoutErrorInternal.SetInternalSourceType(SqlConnectionInternalSourceType.RoutingDestination);
                        _originalClientConnectionId = _clientConnectionId;
                        _routingDestination = serverInfo.UserServerName;

                        // restore properties that could be changed by the environment tokens
                        _currentPacketSize = ConnectionOptions.PacketSize;
                        _currentLanguage = _originalLanguage = ConnectionOptions.CurrentLanguage;
                        CurrentDatabase = _originalDatabase = ConnectionOptions.InitialCatalog;
                        _currentFailoverPartner = null;
                        _instanceName = string.Empty;

                        routingAttempts++;

                        continue; // repeat the loop, but skip code reserved for failed connections (after the catch)
                    }
                    else
                    {
                        break; // leave the while loop -- we've successfully connected
                    }
                }
                catch (SqlException sqlex)
                {
                    if (AttemptRetryADAuthWithTimeoutError(sqlex, connectionOptions, timeout))
                    {
                        continue;
                    }

                    if (null == _parser
                            || TdsParserState.Closed != _parser.State
                            || IsDoNotRetryConnectError(sqlex)
                            || timeout.IsExpired)
                    {       // no more time to try again
                        throw;  // Caller will call LoginFailure()
                    }

                    // Check sleep interval to make sure we won't exceed the timeout
                    //  Do this in the catch block so we can re-throw the current exception
                    if (timeout.MillisecondsRemaining <= sleepInterval)
                    {
                        throw;
                    }
                }

                // We only get here when we failed to connect, but are going to re-try

                // Switch to failover logic if the server provided a partner
                if (null != ServerProvidedFailOverPartner)
                {
                    if (connectionOptions.MultiSubnetFailover)
                    {
                        // connection failed: do not allow failover to server-provided failover partner if MultiSubnetFailover is set
                        throw SQL.MultiSubnetFailoverWithFailoverPartner(serverProvidedFailoverPartner: true, internalConnection: this);
                    }
                    Debug.Assert(ConnectionOptions.ApplicationIntent != ApplicationIntent.ReadOnly, "FAILOVER+AppIntent=RO: Should already fail (at LOGSHIPNODE in OnEnvChange)");

                    _timeoutErrorInternal.ResetAndRestartPhase();
                    _timeoutErrorInternal.SetAndBeginPhase(SqlConnectionTimeoutErrorPhase.PreLoginBegin);
                    _timeoutErrorInternal.SetInternalSourceType(SqlConnectionInternalSourceType.Failover);
                    _timeoutErrorInternal.SetFailoverScenario(true); // this is a failover scenario
                    LoginWithFailover(
                                true,   // start by using failover partner, since we already failed to connect to the primary
                                serverInfo,
                                ServerProvidedFailOverPartner,
                                newPassword,
                                newSecurePassword,
                                redirectedUserInstance,
                                connectionOptions,
                                credential,
                                timeout, 
                                async, cancellationToken);
                    return; // LoginWithFailover successfully connected and handled entire connection setup
                }

                // Sleep for a bit to prevent clogging the network with requests,
                //  then update sleep interval for next iteration (max 1 second interval)
                SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.LoginNoFailover|ADV> {0}, sleeping {1}[milisec]", ObjectID, sleepInterval);
                Thread.Sleep(sleepInterval);
                sleepInterval = (sleepInterval < 500) ? sleepInterval * 2 : 1000;
            }
            _activeDirectoryAuthTimeoutRetryHelper.State = ActiveDirectoryAuthenticationTimeoutRetryState.HasLoggedIn;

            if (null != PoolGroupProviderInfo)
            {
                // We must wait for CompleteLogin to finish for to have the
                // env change from the server to know its designated failover
                // partner; save this information in _currentFailoverPartner.
                PoolGroupProviderInfo.FailoverCheck(false, connectionOptions, ServerProvidedFailOverPartner);
            }
            CurrentDataSource = originalServerInfo.UserServerName;
        }

        // With possible MFA support in all AD auth providers, the duration for acquiring a token can be unpredictable.
        // If a timeout error (client or server) happened, we silently retry if a cached token exists from a previous auth attempt (see GetFedAuthToken)
        private bool AttemptRetryADAuthWithTimeoutError(SqlException sqlex, SqlConnectionString connectionOptions, TimeoutTimer timeout)
        {
            if (!_activeDirectoryAuthTimeoutRetryHelper.CanRetryWithSqlException(sqlex))
            {
                return false;
            }
            // Reset client-side timeout.
            timeout.Reset();
            // When server timeout, the auth context key was already created. Clean it up here.
            _dbConnectionPoolAuthenticationContextKey = null;
            // When server timeouts, connection is doomed. Reset here to allow reconnect.
            UnDoomThisConnection();
            // Change retry state so it only retries once for timeout error.
            _activeDirectoryAuthTimeoutRetryHelper.State = ActiveDirectoryAuthenticationTimeoutRetryState.Retrying;
            return true;
        }

        // Attempt to login to a host that has a failover partner
        //
        // Connection & timeout sequence is
        //      First target, timeout = interval * 1
        //      second target, timeout = interval * 1
        //      sleep for 100ms
        //      First target, timeout = interval * 2
        //      Second target, timeout = interval * 2
        //      sleep for 200ms
        //      First Target, timeout = interval * 3
        //      etc.
        //
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        //  DEVNOTE: The logic in this method is paralleled by the logic in LoginNoFailover.
        //           Changes to either one should be examined to see if they need to be reflected in the other
        // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        private async Task LoginWithFailoverAsync(
                bool useFailoverHost,
                ServerInfo primaryServerInfo,
                string failoverHost,
                string newPassword,
                SecureString newSecurePassword,
                bool redirectedUserInstance,
                SqlConnectionString connectionOptions,
                SqlCredential credential,
                TimeoutTimer timeout,
                bool async,
                CancellationToken cancellationToken
            )
        {
            Debug.Assert(!connectionOptions.MultiSubnetFailover, "MultiSubnetFailover should not be set if failover partner is used");
            SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.LoginWithFailover|ADV> {0}, useFailover={1}[bool], primary={2}, failover={3}", ObjectID, useFailoverHost, primaryServerInfo.UserServerName, failoverHost);

            int sleepInterval = 100;  //milliseconds to sleep (back off) between attempts.
            long timeoutUnitInterval;

            ServerInfo failoverServerInfo = new ServerInfo(connectionOptions, failoverHost, connectionOptions.FailoverPartnerSPN);

            ResolveExtendedServerName(primaryServerInfo, !redirectedUserInstance, connectionOptions);
            if (null == ServerProvidedFailOverPartner)
            {
                ResolveExtendedServerName(failoverServerInfo, !redirectedUserInstance && failoverHost != primaryServerInfo.UserServerName, connectionOptions);
            }

            // Determine unit interval
            if (timeout.IsInfinite)
            {
                timeoutUnitInterval = checked((long)(ADP.FailoverTimeoutStep * ADP.TimerFromSeconds(ADP.DefaultConnectionTimeout)));
            }
            else
            {
                timeoutUnitInterval = checked((long)(ADP.FailoverTimeoutStep * timeout.MillisecondsRemaining));
            }

            // Initialize loop variables
            int attemptNumber = 0;

            // Only three ways out of this loop:
            //  1) Successfully connected
            //  2) Parser threw exception while main timer was expired
            //  3) Parser threw logon failure-related exception (LOGON_FAILED, PASSWORD_EXPIRED, etc)
            //
            //  Of these methods, only #1 exits normally. This preserves the call stack on the exception
            //  back into the parser for the error cases.
            while (true)
            {
                // Set timeout for this attempt, but don't exceed original timer
                long nextTimeoutInterval = checked(timeoutUnitInterval * ((attemptNumber / 2) + 1));
                long milliseconds = timeout.MillisecondsRemaining;
                if (nextTimeoutInterval > milliseconds)
                {
                    nextTimeoutInterval = milliseconds;
                }

                TimeoutTimer intervalTimer = TimeoutTimer.StartMillisecondsTimeout(nextTimeoutInterval);

                // Re-allocate parser each time to make sure state is known
                // RFC 50002652 - if parser was created by previous attempt, dispose it to properly close the socket, if created
                if (_parser != null)
                    _parser.Disconnect();

                _parser = new TdsParser(ConnectionOptions.MARS, ConnectionOptions.Asynchronous);
                Debug.Assert(SniContext.Undefined == Parser._physicalStateObj.SniContext, $"SniContext should be Undefined; actual Value: {Parser._physicalStateObj.SniContext}");

                ServerInfo currentServerInfo;
                if (useFailoverHost)
                {
                    // Primary server may give us a different failover partner than the connection string indicates.  Update it
                    if (null != ServerProvidedFailOverPartner && failoverServerInfo.ResolvedServerName != ServerProvidedFailOverPartner)
                    {
                        SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.LoginWithFailover|ADV> {0}, new failover partner={1}", ObjectID, ServerProvidedFailOverPartner);
                        failoverServerInfo.SetDerivedNames(string.Empty, ServerProvidedFailOverPartner);
                    }
                    currentServerInfo = failoverServerInfo;
                    _timeoutErrorInternal.SetInternalSourceType(SqlConnectionInternalSourceType.Failover);
                }
                else
                {
                    currentServerInfo = primaryServerInfo;
                    _timeoutErrorInternal.SetInternalSourceType(SqlConnectionInternalSourceType.Principle);
                }

                try
                {
                    // Attempt login.  Use timerInterval for attempt timeout unless infinite timeout was requested.
                    await AttemptOneLoginAsync(
                            currentServerInfo,
                            newPassword,
                            newSecurePassword,
                            intervalTimer,
                            async,
                            cancellationToken,
                            withFailover: true);

                    if (RoutingInfo != null)
                    {
                        // We are in login with failover scenation and server sent routing information
                        // If it is read-only routing - we did not supply AppIntent=RO (it should be checked before)
                        // If it is something else, not known yet (future server) - this client is not designed to support this.
                        // In any case, server should not have sent the routing info.
                        SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.LoginWithFailover> Routed to {0}", RoutingInfo.ServerName);
                        throw SQL.ROR_UnexpectedRoutingInfo(this);
                    }
                    break; // leave the while loop -- we've successfully connected
                }
                catch (SqlException sqlex)
                {
                    if (AttemptRetryADAuthWithTimeoutError(sqlex, connectionOptions, timeout))
                    {
                        continue;
                    }

                    if (IsDoNotRetryConnectError(sqlex)
                            || timeout.IsExpired)
                    {       // no more time to try again
                        throw;  // Caller will call LoginFailure()
                    }

                    if (IsConnectionDoomed)
                    {
                        throw;
                    }

                    if (1 == attemptNumber % 2)
                    {
                        // Check sleep interval to make sure we won't exceed the original timeout
                        //  Do this in the catch block so we can re-throw the current exception
                        if (timeout.MillisecondsRemaining <= sleepInterval)
                        {
                            throw;
                        }
                    }
                }

                // We only get here when we failed to connect, but are going to re-try

                // After trying to connect to both servers fails, sleep for a bit to prevent clogging
                //  the network with requests, then update sleep interval for next iteration (max 1 second interval)
                if (1 == attemptNumber % 2)
                {
                    SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.LoginWithFailover|ADV> {0}, sleeping {1}[milisec]", ObjectID, sleepInterval);
                    Thread.Sleep(sleepInterval);
                    sleepInterval = (sleepInterval < 500) ? sleepInterval * 2 : 1000;
                }

                // Update attempt number and target host
                attemptNumber++;
                useFailoverHost = !useFailoverHost;
            }

            // If we get here, connection/login succeeded!  Just a few more checks & record-keeping
            _activeDirectoryAuthTimeoutRetryHelper.State = ActiveDirectoryAuthenticationTimeoutRetryState.HasLoggedIn;

            // if connected to failover host, but said host doesn't have DbMirroring set up, throw an error
            if (useFailoverHost && null == ServerProvidedFailOverPartner)
            {
                throw SQL.InvalidPartnerConfiguration(failoverHost, CurrentDatabase);
            }

            if (null != PoolGroupProviderInfo)
            {
                // We must wait for CompleteLogin to finish for to have the
                // env change from the server to know its designated failover
                // partner; save this information in _currentFailoverPartner.
                PoolGroupProviderInfo.FailoverCheck(useFailoverHost, connectionOptions, ServerProvidedFailOverPartner);
            }
            CurrentDataSource = (useFailoverHost ? failoverHost : primaryServerInfo.UserServerName);
        }

        // Common code path for making one attempt to establish a connection and log in to server.
        private async Task AttemptOneLoginAsync(
                                ServerInfo serverInfo,
                                string newPassword,
                                SecureString newSecurePassword,
                                TimeoutTimer timeout,
                                bool async,
                                CancellationToken cancellationToken,
                                bool withFailover = false)
        {
            SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.AttemptOneLogin|ADV> {0}, timout={1}[msec], server={2}", ObjectID, timeout.MillisecondsRemaining, serverInfo.ExtendedServerName);
            RoutingInfo = null; // forget routing information 

            _parser._physicalStateObj.SniContext = SniContext.Snix_Connect;
            
            LoginHandler loginHandler = new();
            
            loginHandler.ConnectAsync(serverInfo,
                            this,
                            timeout,
                            ConnectionOptions,
                            withFailover);

            _timeoutErrorInternal.EndPhase(SqlConnectionTimeoutErrorPhase.ConsumePreLoginHandshake);
            _timeoutErrorInternal.SetAndBeginPhase(SqlConnectionTimeoutErrorPhase.LoginBegin);

            _parser._physicalStateObj.SniContext = SniContext.Snix_Login;
            this.Login(serverInfo, timeout, newPassword, newSecurePassword, ConnectionOptions.Encrypt);

            _timeoutErrorInternal.EndPhase(SqlConnectionTimeoutErrorPhase.ProcessConnectionAuth);
            _timeoutErrorInternal.SetAndBeginPhase(SqlConnectionTimeoutErrorPhase.PostLogin);

            CompleteLogin(!ConnectionOptions.Pooling);

            _timeoutErrorInternal.EndPhase(SqlConnectionTimeoutErrorPhase.PostLogin);
        }
    }
}

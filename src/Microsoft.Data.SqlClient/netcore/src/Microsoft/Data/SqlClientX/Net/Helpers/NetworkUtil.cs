// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Net.Security;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using Microsoft.Data.Common;
using Microsoft.Data.ProviderBase;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using System.Net.Sockets;
using Microsoft.Data.SqlClientX.Net.Types;
using Microsoft.Data.SqlClient.SNI;
using System.Collections.Generic;

namespace Microsoft.Data.SqlClientX.Net.Helpers
{
    internal static class NetworkUtil
    {
        /// <summary>
        /// We only validate Server name in Certificate to match with "targetServerName".
        /// Certificate validation and chain trust validations are done by SSLStream class [System.Net.Security.SecureChannel.VerifyRemoteCertificate method]
        /// This method is called as a result of callback for SSL Stream Certificate validation.
        /// </summary>
        /// <param name="targetServerName">Server that client is expecting to connect to</param>
        /// <param name="cert">X.509 certificate</param>
        /// <param name="policyErrors">Policy errors</param>
        /// <returns>True if certificate is valid</returns>
        internal static bool ValidateSslServerCertificate(string targetServerName, X509Certificate cert, SslPolicyErrors policyErrors)
        {
            using (TrySNIEventScope.Create("Util.ValidateSslServerCertificate | SNI | SCOPE | INFO | Entering Scope {0} "))
            {
                if (policyErrors == SslPolicyErrors.None)
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.INFO, "targetServerName {0}, SSL Server certificate not validated as PolicyErrors set to None.", args0: targetServerName);
                    return true;
                }

                // If we get to this point then there is a ssl policy flag.
                StringBuilder messageBuilder = new();
                if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "targetServerName {0}, SslPolicyError {1}, SSL Policy certificate chain has errors.", args0: targetServerName, args1: policyErrors);

                    // get the chain status from the certificate
                    X509Certificate2 cert2 = cert as X509Certificate2;
                    X509Chain chain = new();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
                    StringBuilder chainStatusInformation = new();
                    bool chainIsValid = chain.Build(cert2);
                    Debug.Assert(!chainIsValid, "RemoteCertificateChainError flag is detected, but certificate chain is valid.");
                    if (!chainIsValid)
                    {
                        foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                        {
                            chainStatusInformation.Append($"{chainStatus.StatusInformation}, [Status: {chainStatus.Status}]");
                            chainStatusInformation.AppendLine();
                        }
                    }
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "targetServerName {0}, SslPolicyError {1}, SSL Policy certificate chain has errors. ChainStatus {2}", args0: targetServerName, args1: policyErrors, args2: chainStatusInformation);
                    messageBuilder.AppendFormat(Strings.SQL_RemoteCertificateChainErrors, chainStatusInformation);
                    messageBuilder.AppendLine();
                }

                if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "targetServerName {0}, SSL Policy invalidated certificate.", args0: targetServerName);
                    messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNotAvailable);
                }

                if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                {
#if NET7_0_OR_GREATER
                    X509Certificate2 cert2 = cert as X509Certificate2;
                    if (!cert2.MatchesHostname(targetServerName))
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "targetServerName {0}, Target Server name or HNIC does not match the Subject/SAN in Certificate.", args0: targetServerName);
                        messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNameMismatch);
                    }
#else
                    // To Do: include certificate SAN (Subject Alternative Name) check.
                    string certServerName = cert.Subject.Substring(cert.Subject.IndexOf('=') + 1);

                    // Verify that target server name matches subject in the certificate
                    if (targetServerName.Length > certServerName.Length)
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "targetServerName {0}, Target Server name is of greater length than Subject in Certificate.", args0: targetServerName);
                        messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNameMismatch);
                    }
                    else if (targetServerName.Length == certServerName.Length)
                    {
                        // Both strings have the same length, so targetServerName must be a FQDN
                        if (!targetServerName.Equals(certServerName, StringComparison.OrdinalIgnoreCase))
                        {
                            SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "targetServerName {0}, Target Server name does not match Subject in Certificate.", args0: targetServerName);
                            messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNameMismatch);
                        }
                    }
                    else
                    {
                        if (string.Compare(targetServerName, 0, certServerName, 0, targetServerName.Length, StringComparison.OrdinalIgnoreCase) != 0)
                        {
                            SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "targetServerName {0}, Target Server name does not match Subject in Certificate.", args0: targetServerName);
                            messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNameMismatch);
                        }

                        // Server name matches cert name for its whole length, so ensure that the
                        // character following the server name is a '.'. This will avoid
                        // having server name "ab" match "abc.corp.company.com"
                        // (Names have different lengths, so the target server can't be a FQDN.)
                        if (certServerName[targetServerName.Length] != '.')
                        {
                            SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "targetServerName {0}, Target Server name does not match Subject in Certificate.", args0: targetServerName);
                            messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNameMismatch);
                        }
                    }
#endif
                }

                if (messageBuilder.Length > 0)
                {
                    throw ADP.SSLCertificateAuthenticationException(messageBuilder.ToString());
                }

                SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.INFO, " Remote certificate with subject: {0}, validated successfully.", args0: cert.Subject);
                return true;
            }
        }

        /// <summary>
        /// We validate the provided certificate provided by the client with the one from the server to see if it matches.
        /// Certificate validation and chain trust validations are done by SSLStream class [System.Net.Security.SecureChannel.VerifyRemoteCertificate method]
        /// This method is called as a result of callback for SSL Stream Certificate validation.
        /// </summary>
        /// <param name="clientCert">X.509 certificate provided by the client</param>
        /// <param name="serverCert">X.509 certificate provided by the server</param>
        /// <param name="policyErrors">Policy errors</param>
        /// <returns>True if certificate is valid</returns>
        internal static bool ValidateSslServerCertificate(X509Certificate clientCert, X509Certificate serverCert, SslPolicyErrors policyErrors)
        {
            using (TrySNIEventScope.Create("Util.ValidateSslServerCertificate | SNI | SCOPE | INFO | Entering Scope {0} "))
            {
                if (policyErrors == SslPolicyErrors.None)
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.INFO, "serverCert {0}, SSL Server certificate not validated as PolicyErrors set to None.", args0: clientCert.Subject);
                    return true;
                }

                StringBuilder messageBuilder = new();
                if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                {
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "serverCert {0}, SSL Server certificate not validated as PolicyErrors set to RemoteCertificateNotAvailable.", args0: clientCert.Subject);
                    messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNotAvailable);
                }

                if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
                {
                    // get the chain status from the server certificate
                    X509Certificate2 cert2 = serverCert as X509Certificate2;
                    X509Chain chain = new();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
                    StringBuilder chainStatusInformation = new();
                    bool chainIsValid = chain.Build(cert2);
                    Debug.Assert(!chainIsValid, "RemoteCertificateChainError flag is detected, but certificate chain is valid.");
                    if (!chainIsValid)
                    {
                        foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                        {
                            chainStatusInformation.Append($"{chainStatus.StatusInformation}, [Status: {chainStatus.Status}]");
                            chainStatusInformation.AppendLine();
                        }
                    }
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(Common), EventType.ERR, "certificate subject from server is {0}, and does not match with the certificate provided client.", args0: cert2.SubjectName.Name);
                    messageBuilder.AppendFormat(Strings.SQL_RemoteCertificateChainErrors, chainStatusInformation);
                    messageBuilder.AppendLine();
                }

                if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                {
#if NET7_0_OR_GREATER
                    X509Certificate2 s_cert = serverCert as X509Certificate2;
                    X509Certificate2 c_cert = clientCert as X509Certificate2;

                    if (!s_cert.MatchesHostname(c_cert.SubjectName.Name))
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent(nameof(Common), EventType.ERR, "certificate from server does not match with the certificate provided client.", args0: s_cert.Subject);
                        messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNameMismatch);
                    }
#else
                    // Verify that subject name matches
                    if (serverCert.Subject != clientCert.Subject)
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent(nameof(Common), EventType.ERR, "certificate subject from server is {0}, and does not match with the certificate provided client.", args0: serverCert.Subject);
                        messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNameMismatch);
                    }

                    if (!serverCert.Equals(clientCert))
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent(nameof(Common), EventType.ERR, "certificate from server does not match with the certificate provided client.", args0: serverCert.Subject);
                        messageBuilder.AppendLine(Strings.SQL_RemoteCertificateNameMismatch);
                    }
#endif
                }

                if (messageBuilder.Length > 0)
                {
                    throw ADP.SSLCertificateAuthenticationException(messageBuilder.ToString());
                }

                SqlClientEventSource.Log.TrySNITraceEvent(nameof(Common), EventType.INFO, "certificate subject {0}, Client certificate validated successfully.", args0: clientCert.Subject);
                return true;
            }
        }

        internal static async Task<IPAddress[]> GetDnsIpAddressesAsync(string serverName, bool async, CancellationToken cancellationToken)
        {
            using (TrySNIEventScope.Create(nameof(GetDnsIpAddressesAsync)))
            {
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.INFO, "Getting DNS host entries for serverName {0}.", args0: serverName);
                return async
                    ? await Dns.GetHostAddressesAsync(serverName, cancellationToken)
                    : Dns.GetHostAddresses(serverName);
            }
        }

        /// <summary>
        /// Sets last error encountered for SNI
        /// </summary>
        /// <param name="provider">SNI provider</param>
        /// <param name="nativeError">Native error code</param>
        /// <param name="sniError">SNI error code</param>
        /// <param name="errorMessage">Error message</param>
        /// <returns></returns>
        internal static uint ReportSNIError(Providers provider, uint nativeError, uint sniError, string errorMessage)
        {
            SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "Provider = {0}, native Error = {1}, SNI Error = {2}, Error Message = {3}", args0: provider, args1: nativeError, args2: sniError, args3: errorMessage);
            return SetLastError(new SqlNetworkError(provider, nativeError, sniError, errorMessage));
        }

        /// <summary>
        /// Sets last error encountered for SNI
        /// </summary>
        /// <param name="provider">SNI provider</param>
        /// <param name="sniError">SNI error code</param>
        /// <param name="sniException">SNI Exception</param>
        /// <param name="nativeErrorCode">Native SNI error code</param>
        /// <returns></returns>
        internal static uint ReportSNIError(Providers provider, uint sniError, Exception sniException, uint nativeErrorCode = 0)
        {
            SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "Provider = {0}, SNI Error = {1}, Exception = {2}", args0: provider, args1: sniError, args2: sniException?.Message);
            return SetLastError(new SqlNetworkError(provider, sniError, sniException, nativeErrorCode));
        }

        /// <summary>
        /// Get last SNI error on this thread
        /// </summary>
        /// <returns></returns>
        internal static SqlNetworkError GetLastError()
        {
            return GlobalErrorHandler.Instance.LastError;
        }

        /// <summary>
        /// Create a Messenger instance
        /// </summary>
        /// <param name="fullServerName">Full server name from connection string</param>
        /// <param name="timeout">Timer expiration</param>
        /// <param name="instanceName">Instance name</param>
        /// <param name="spnBuffer">SPN</param>
        /// <param name="serverSPN">pre-defined SPN</param>
        /// <param name="flushCache">Flush packet cache</param>
        /// <param name="async">Asynchronous connection</param>
        /// <param name="parallel">Attempt parallel connects</param>
        /// <param name="isIntegratedSecurity"></param>
        /// <param name="ipPreference">IP address preference</param>
        /// <param name="cachedFQDN">Used for DNS Cache</param>
        /// <param name="pendingDNSInfo">Used for DNS Cache</param>
        /// <param name="tlsFirst">Support TDS8.0</param>
        /// <param name="hostNameInCertificate">Used for the HostName in certificate</param>
        /// <param name="serverCertificateFilename">Used for the path to the Server Certificate</param>
        /// <param name="cancellationToken">Cancellation Token</param>
        /// <returns>SNI handle</returns>
        internal static async Task<Messenger> CreateMessengerAsync(
            string fullServerName,
            TimeoutTimer timeout,
            byte[] instanceName,
            byte[][] spnBuffer,
            string serverSPN,
            bool flushCache,
            bool async,
            bool parallel,
            bool isIntegratedSecurity,
            SqlConnectionIPAddressPreference ipPreference,
            string cachedFQDN,
            SqlDnsInfo pendingDNSInfo,
            bool tlsFirst,
            string hostNameInCertificate,
            string serverCertificateFilename,
            CancellationToken cancellationToken)
        {
            instanceName = new byte[1];

            bool errorWithLocalDBProcessing;
            string localDBDataSource = GetLocalDBDataSource(fullServerName, out errorWithLocalDBProcessing);

            if (errorWithLocalDBProcessing)
            {
                return null;
            }
            // If a localDB Data source is available, we need to use it.
            fullServerName = localDBDataSource ?? fullServerName;

            SqlDataSource details = SqlDataSource.ParseServerName(fullServerName);
            if (details == null)
            {
                return null;
            }

            Messenger messenger = null;
            switch (details._connectionProtocol)
            {
                case SqlDataSource.Protocol.Admin:
                case SqlDataSource.Protocol.None: // default to using tcp if no protocol is provided
                case SqlDataSource.Protocol.TCP:
                    messenger = await CreateAndOpenTcpMessengerAsync(details, timeout, parallel, ipPreference, cachedFQDN, pendingDNSInfo,
                        tlsFirst, hostNameInCertificate, serverCertificateFilename, async, cancellationToken);
                    break;
                case SqlDataSource.Protocol.NP:
                    // TODO messenger = await CreateNpMessengerAsync(details, timeout, parallel, tlsFirst);
                    Debug.Fail($"Unexpected connection protocol: {details._connectionProtocol}");
                    break;
                default:
                    Debug.Fail($"Unexpected connection protocol: {details._connectionProtocol}");
                    break;
            }

            if (isIntegratedSecurity)
            {
                try
                {
                    spnBuffer = await GetSqlServerSPNsAsync(details, serverSPN, async, cancellationToken);
                }
                catch (Exception e)
                {
                    GlobalErrorHandler.Instance.LastError = new SqlNetworkError(Providers.INVALID_PROV, Constants.ErrorSpnLookup, e);
                }
            }

            SqlClientEventSource.Log.TryTraceEvent("SNIProxy.CreateConnectionHandle | Info | Session Id {0}, SNI Handle Type: {1}", messenger?.ConnectionId, messenger?.GetType());
            return messenger;
        }

        #region Private Helpers

        /// <summary>
        /// Sets last error encountered for SNI
        /// </summary>
        /// <param name="error">SNI error</param>
        /// <returns></returns>
        private static uint SetLastError(SqlNetworkError error)
        {
            GlobalErrorHandler.Instance.LastError = error;
            return TdsEnums.SNI_ERROR;
        }

        private static async Task<byte[][]> GetSqlServerSPNsAsync(SqlDataSource dataSource, string serverSPN, bool async, CancellationToken cancellationToken)
        {
            Debug.Assert(!string.IsNullOrWhiteSpace(dataSource.ServerName));
            if (!string.IsNullOrWhiteSpace(serverSPN))
            {
                return new byte[1][] { Encoding.Unicode.GetBytes(serverSPN) };
            }

            string hostName = dataSource.ServerName;
            string postfix = null;
            if (dataSource.Port != -1)
            {
                postfix = dataSource.Port.ToString();
            }
            else if (!string.IsNullOrWhiteSpace(dataSource.InstanceName))
            {
                postfix = dataSource._connectionProtocol == SqlDataSource.Protocol.TCP ? dataSource.ResolvedPort.ToString() : dataSource.InstanceName;
            }

            SqlClientEventSource.Log.TryTraceEvent("SNIProxy.GetSqlServerSPN | Info | ServerName {0}, InstanceName {1}, Port {2}, postfix {3}", dataSource?.ServerName, dataSource?.InstanceName, dataSource?.Port, postfix);
            return await GetSqlServerSPNsAsync(hostName, postfix, dataSource._connectionProtocol, async, cancellationToken);
        }

        private static async Task<byte[][]> GetSqlServerSPNsAsync(string hostNameOrAddress, string portOrInstanceName, SqlDataSource.Protocol protocol, bool async, CancellationToken cancellationToken)
        {
            Debug.Assert(!string.IsNullOrWhiteSpace(hostNameOrAddress));
            IPHostEntry hostEntry = null;
            string fullyQualifiedDomainName;
            try
            {
                hostEntry = async 
                    ? await Dns.GetHostEntryAsync(hostNameOrAddress, cancellationToken)
                    : Dns.GetHostEntry(hostNameOrAddress);
            }
            catch (SocketException)
            {
                // A SocketException can occur while resolving the hostname.
                // We will fallback on using hostname from the connection string in the finally block
            }
            finally
            {
                // If the DNS lookup failed, then resort to using the user provided hostname to construct the SPN.
                fullyQualifiedDomainName = hostEntry?.HostName ?? hostNameOrAddress;
            }

            string serverSpn = Constants.SqlServerSpnHeader + "/" + fullyQualifiedDomainName;

            if (!string.IsNullOrWhiteSpace(portOrInstanceName))
            {
                serverSpn += ":" + portOrInstanceName;
            }
            else if (protocol == SqlDataSource.Protocol.None || protocol == SqlDataSource.Protocol.TCP) // Default is TCP
            {
                string serverSpnWithDefaultPort = serverSpn + $":{Constants.DefaultSqlServerPort}";
                // Set both SPNs with and without Port as Port is optional for default instance
                SqlClientEventSource.Log.TryAdvancedTraceEvent("SNIProxy.GetSqlServerSPN | Info | ServerSPNs {0} and {1}", serverSpn, serverSpnWithDefaultPort);
                return new byte[][] { Encoding.Unicode.GetBytes(serverSpn), Encoding.Unicode.GetBytes(serverSpnWithDefaultPort) };
            }
            // else Named Pipes do not need to valid port

            SqlClientEventSource.Log.TryAdvancedTraceEvent("SNIProxy.GetSqlServerSPN | Info | ServerSPN {0}", serverSpn);
            return new byte[][] { Encoding.Unicode.GetBytes(serverSpn) };
        }

        // TODO SqlClientX Make method true async
        /// <summary>
        /// Creates an SNITCPHandle object
        /// </summary>
        /// <param name="datasource">Data source</param>
        /// <param name="timeout">Timer expiration</param>
        /// <param name="parallel">Should MultiSubnetFailover be used</param>
        /// <param name="ipPreference">IP address preference</param>
        /// <param name="cachedFQDN">Key for DNS Cache</param>
        /// <param name="pendingDNSInfo">Used for DNS Cache</param>
        /// <param name="tlsFirst">Support TDS8.0</param>
        /// <param name="hostNameInCertificate">Host name in certificate</param>
        /// <param name="serverCertificateFilename">Used for the path to the Server Certificate</param>
        /// <param name="async">Whether the method is called from an Async API</param>
        /// <param name="cancellationToken">Cancellation Token</param>
        /// <returns>TcpMessenger</returns>
        private static async Task<TcpMessenger> CreateAndOpenTcpMessengerAsync(
            SqlDataSource datasource,
            TimeoutTimer timeout,
            bool parallel,
            SqlConnectionIPAddressPreference ipPreference,
            string cachedFQDN,
            SqlDnsInfo pendingDNSInfo,
            bool tlsFirst,
            string hostNameInCertificate,
            string serverCertificateFilename,
            bool async,
            CancellationToken cancellationToken)
        {
            // TCP Format:
            // tcp:<host name>\<instance name>
            // tcp:<host name>,<TCP/IP port number>

            string hostName = datasource.ServerName;
            if (string.IsNullOrWhiteSpace(hostName))
            {
                GlobalErrorHandler.Instance.LastError = new SqlNetworkError(Providers.TCP_PROV, 0, Constants.InvalidConnStringError, Strings.SNI_ERROR_25);
                return null;
            }

            int port = -1;
            bool isAdminConnection = datasource._connectionProtocol == SqlDataSource.Protocol.Admin;
            if (datasource.IsSsrpRequired)
            {
                try
                {
                    // TODO SqlClientX Make calls true async
                    datasource.ResolvedPort = port = isAdminConnection ?
                            GetDacPortByInstanceName(hostName, datasource.InstanceName, timeout, parallel, ipPreference) :
                            GetPortByInstanceName(hostName, datasource.InstanceName, timeout, parallel, ipPreference);
                }
                catch (SocketException se)
                {
                    GlobalErrorHandler.Instance.LastError = new SqlNetworkError(Providers.TCP_PROV, Constants.ErrorLocatingServerInstance, se);
                    return null;
                }
            }
            else if (datasource.Port != -1)
            {
                port = datasource.Port;
            }
            else
            {
                port = isAdminConnection ? Constants.DefaultSqlServerDacPort : Constants.DefaultSqlServerPort;
            }

            var messenger = new TcpMessenger(new(hostName, port, tlsFirst, hostNameInCertificate, serverCertificateFilename, cachedFQDN, timeout, pendingDNSInfo, ipPreference));
            await messenger.OpenAsync(parallel, async, cancellationToken);
            return messenger;
        }

        // TODO SqlClientX Implement NpMessenger
        ///// <summary>
        ///// Creates an SNINpHandle object
        ///// </summary>
        ///// <param name="details">Data source</param>
        ///// <param name="timeout">Timer expiration</param>
        ///// <param name="parallel">Should MultiSubnetFailover be used. Only returns an error for named pipes.</param>
        ///// <param name="tlsFirst"></param>
        ///// <returns>SNINpHandle</returns>
        //private static SNINpHandle CreateNpHandle(SqlDataSource details, TimeoutTimer timeout, bool parallel, bool tlsFirst)
        //{
        //    if (parallel)
        //    {
        //        // Connecting to a SQL Server instance using the MultiSubnetFailover connection option is only supported when using the TCP protocol
        //        SNICommon.ReportSNIError(SNIProviders.NP_PROV, 0, SNICommon.MultiSubnetFailoverWithNonTcpProtocol, Strings.SNI_ERROR_49);
        //        return null;
        //    }
        //    return new SNINpHandle(details.PipeHostName, details.PipeName, timeout, tlsFirst);
        //}

        /// <summary>
        /// Gets the Local db Named pipe data source if the input is a localDB server.
        /// </summary>
        /// <param name="fullServerName">The data source</param>
        /// <param name="error">Set true when an error occurred while getting LocalDB up</param>
        /// <returns></returns>
        private static string GetLocalDBDataSource(string fullServerName, out bool error)
        {
            string localDBConnectionString = null;
            string localDBInstance = SqlDataSource.GetLocalDBInstance(fullServerName, out bool isBadLocalDBDataSource);

            if (isBadLocalDBDataSource)
            {
                error = true;
                return null;
            }

            else if (!string.IsNullOrEmpty(localDBInstance))
            {
                // We have successfully received a localDBInstance which is valid.
                Debug.Assert(!string.IsNullOrWhiteSpace(localDBInstance), "Local DB Instance name cannot be empty.");
                localDBConnectionString = LocalDB.GetLocalDBConnectionString(localDBInstance);

                if (fullServerName == null || string.IsNullOrEmpty(localDBConnectionString))
                {
                    // The Last error is set in LocalDB.GetLocalDBConnectionString. We don't need to set Last here.
                    error = true;
                    return null;
                }
            }
            error = false;
            return localDBConnectionString;
        }

        // TODO SqlClientX Make method true async
        /// <summary>
        /// Finds instance port number for given instance name.
        /// </summary>
        /// <param name="browserHostName">SQL Sever Browser hostname</param>
        /// <param name="instanceName">instance name to find port number</param>
        /// <param name="timeout">Connection timer expiration</param>
        /// <param name="allIPsInParallel">query all resolved IP addresses in parallel</param>
        /// <param name="ipPreference">IP address preference</param>
        /// <returns>port number for given instance name</returns>
        internal static int GetPortByInstanceName(string browserHostName, string instanceName, TimeoutTimer timeout, bool allIPsInParallel, SqlConnectionIPAddressPreference ipPreference)
        {
            Debug.Assert(!string.IsNullOrWhiteSpace(browserHostName), "browserHostName should not be null, empty, or whitespace");
            Debug.Assert(!string.IsNullOrWhiteSpace(instanceName), "instanceName should not be null, empty, or whitespace");
            using (TrySNIEventScope.Create(nameof(NetworkUtil)))
            {
                byte[] instanceInfoRequest = CreateInstanceInfoRequest(instanceName);
                byte[] responsePacket = null;
                try
                {
                    responsePacket = SendUDPRequest(browserHostName, Constants.SqlServerBrowserPort, instanceInfoRequest, timeout, allIPsInParallel, ipPreference);
                }
                catch (SocketException se)
                {
                    // A SocketException is possible for an instance name that doesn't exist.
                    // If there are multiple IP addresses and one of them fails with a SocketException but
                    // others simply don't respond because the instance name is invalid, we want to return
                    // the same error as if the response was empty. The higher error suits all scenarios.
                    // But log it, just in case there is a different, underlying issue that support needs
                    // to troubleshoot.
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(NetworkUtil), EventType.ERR, "SocketException Message = {0}", args0: se?.Message);
                    throw;
                }

                const byte SvrResp = 0x05;
                if (responsePacket == null || responsePacket.Length <= 3 || responsePacket[0] != SvrResp ||
                    BitConverter.ToUInt16(responsePacket, 1) != responsePacket.Length - 3)
                {
                    throw new SocketException();
                }

                string serverMessage = Encoding.ASCII.GetString(responsePacket, 3, responsePacket.Length - 3);

                string[] elements = serverMessage.Split(Constants.SemicolonSeparator);
                int tcpIndex = Array.IndexOf(elements, "tcp");
                if (tcpIndex < 0 || tcpIndex == elements.Length - 1)
                {
                    throw new SocketException();
                }

                return ushort.Parse(elements[tcpIndex + 1]);
            }
        }

        /// <summary>
        /// Creates instance port lookup request (CLNT_UCAST_INST) for given instance name.
        /// </summary>
        /// <param name="instanceName">instance name to lookup port</param>
        /// <returns>Byte array of instance port lookup request (CLNT_UCAST_INST)</returns>
        private static byte[] CreateInstanceInfoRequest(string instanceName)
        {
            Debug.Assert(!string.IsNullOrWhiteSpace(instanceName), "instanceName should not be null, empty, or whitespace");
            using (TrySNIEventScope.Create(nameof(NetworkUtil)))
            {
                const byte ClntUcastInst = 0x04;
                instanceName += char.MinValue;
                int byteCount = Encoding.ASCII.GetByteCount(instanceName);

                byte[] requestPacket = new byte[byteCount + 1];
                requestPacket[0] = ClntUcastInst;
                Encoding.ASCII.GetBytes(instanceName, 0, instanceName.Length, requestPacket, 1);

                return requestPacket;
            }
        }

        // TODO SqlClientX Make method true async
        /// <summary>
        /// Finds DAC port for given instance name.
        /// </summary>
        /// <param name="browserHostName">SQL Sever Browser hostname</param>
        /// <param name="instanceName">instance name to lookup DAC port</param>
        /// <param name="timeout">Connection timer expiration</param>
        /// <param name="allIPsInParallel">query all resolved IP addresses in parallel</param>
        /// <param name="ipPreference">IP address preference</param>
        /// <returns>DAC port for given instance name</returns>
        internal static async Task<int> GetDacPortByInstanceNameAsync(string browserHostName, string instanceName, TimeoutTimer timeout, bool allIPsInParallel, SqlConnectionIPAddressPreference ipPreference, bool async, CancellationToken cancellationToken)
        {
            Debug.Assert(!string.IsNullOrWhiteSpace(browserHostName), "browserHostName should not be null, empty, or whitespace");
            Debug.Assert(!string.IsNullOrWhiteSpace(instanceName), "instanceName should not be null, empty, or whitespace");

            byte[] dacPortInfoRequest = CreateDacPortInfoRequest(instanceName);
            byte[] responsePacket = await SendUDPRequestAsync(browserHostName, Constants.SqlServerBrowserPort, dacPortInfoRequest, timeout, allIPsInParallel, ipPreference, async, cancellationToken);

            const byte SvrResp = 0x05;
            const byte ProtocolVersion = 0x01;
            const byte RespSize = 0x06;
            if (responsePacket == null || responsePacket.Length <= 4 || responsePacket[0] != SvrResp ||
                BitConverter.ToUInt16(responsePacket, 1) != RespSize || responsePacket[3] != ProtocolVersion)
            {
                throw new SocketException();
            }

            int dacPort = BitConverter.ToUInt16(responsePacket, 4);
            return dacPort;
        }

        /// <summary>
        /// Creates DAC port lookup request (CLNT_UCAST_DAC) for given instance name.
        /// </summary>
        /// <param name="instanceName">instance name to lookup DAC port</param>
        /// <returns>Byte array of DAC port lookup request (CLNT_UCAST_DAC)</returns>
        private static byte[] CreateDacPortInfoRequest(string instanceName)
        {
            Debug.Assert(!string.IsNullOrWhiteSpace(instanceName), "instanceName should not be null, empty, or whitespace");

            const byte ClntUcastDac = 0x0F;
            const byte ProtocolVersion = 0x01;
            instanceName += char.MinValue;
            int byteCount = Encoding.ASCII.GetByteCount(instanceName);

            byte[] requestPacket = new byte[byteCount + 2];
            requestPacket[0] = ClntUcastDac;
            requestPacket[1] = ProtocolVersion;
            Encoding.ASCII.GetBytes(instanceName, 0, instanceName.Length, requestPacket, 2);

            return requestPacket;
        }

        private class SsrpResult
        {
            public byte[] ResponsePacket;
            public Exception Error;
        }

        // TODO SqlClientX Make method true async
        /// <summary>
        /// Sends request to server, and receives response from server by UDP.
        /// </summary>
        /// <param name="browserHostname">UDP server hostname</param>
        /// <param name="port">UDP server port</param>
        /// <param name="requestPacket">request packet</param>
        /// <param name="timeout">Connection timer expiration</param>
        /// <param name="allIPsInParallel">query all resolved IP addresses in parallel</param>
        /// <param name="ipPreference">IP address preference</param>
        /// <returns>response packet from UDP server</returns>
        private static byte[] SendUDPRequest(string browserHostname, int port, byte[] requestPacket, TimeoutTimer timeout, bool allIPsInParallel, SqlConnectionIPAddressPreference ipPreference)
        {
            using (TrySNIEventScope.Create(nameof(SSRP)))
            {
                Debug.Assert(!string.IsNullOrWhiteSpace(browserHostname), "browserhostname should not be null, empty, or whitespace");
                Debug.Assert(port >= 0 && port <= 65535, "Invalid port");
                Debug.Assert(requestPacket != null && requestPacket.Length > 0, "requestPacket should not be null or 0-length array");

                if (IPAddress.TryParse(browserHostname, out IPAddress address))
                {
                    // TODO SqlClientX make async request
                    SsrpResult response = SendUDPRequest(new IPAddress[] { address }, port, requestPacket, allIPsInParallel);
                    if (response != null && response.ResponsePacket != null)
                        return response.ResponsePacket;
                    else if (response != null && response.Error != null)
                        throw response.Error;
                    else
                        return null;
                }

                // TODO SqlClientX Replace with GetDnsIpAddressesAsync and pass required params
                IPAddress[] ipAddresses = timeout.IsInfinite
                    ? SNICommon.GetDnsIpAddresses(browserHostname)
                    : SNICommon.GetDnsIpAddresses(browserHostname, timeout);

                Debug.Assert(ipAddresses.Length > 0, "DNS should throw if zero addresses resolve");
                IPAddress[] ipv4Addresses = null;
                IPAddress[] ipv6Addresses = null;
                switch (ipPreference)
                {
                    case SqlConnectionIPAddressPreference.IPv4First:
                        {
                            SplitIPv4AndIPv6(ipAddresses, out ipv4Addresses, out ipv6Addresses);

                            // TODO SqlClientX make async request
                            SsrpResult response4 = SendUDPRequest(ipv4Addresses, port, requestPacket, allIPsInParallel);
                            if (response4 != null && response4.ResponsePacket != null)
                            {
                                return response4.ResponsePacket;
                            }

                            // TODO SqlClientX make async request
                            SsrpResult response6 = SendUDPRequest(ipv6Addresses, port, requestPacket, allIPsInParallel);
                            if (response6 != null && response6.ResponsePacket != null)
                            {
                                return response6.ResponsePacket;
                            }

                            // No responses so throw first error
                            if (response4 != null && response4.Error != null)
                            {
                                throw response4.Error;
                            }
                            else if (response6 != null && response6.Error != null)
                            {
                                throw response6.Error;
                            }

                            break;
                        }
                    case SqlConnectionIPAddressPreference.IPv6First:
                        {
                            SplitIPv4AndIPv6(ipAddresses, out ipv4Addresses, out ipv6Addresses);

                            // TODO SqlClientX make async request
                            SsrpResult response6 = SendUDPRequest(ipv6Addresses, port, requestPacket, allIPsInParallel);
                            if (response6 != null && response6.ResponsePacket != null)
                            {
                                return response6.ResponsePacket;
                            }

                            // TODO SqlClientX make async request
                            SsrpResult response4 = SendUDPRequest(ipv4Addresses, port, requestPacket, allIPsInParallel);
                            if (response4 != null && response4.ResponsePacket != null)
                            {
                                return response4.ResponsePacket;
                            }

                            // No responses so throw first error
                            if (response6 != null && response6.Error != null)
                            {
                                throw response6.Error;
                            }
                            else if (response4 != null && response4.Error != null)
                            {
                                throw response4.Error;
                            }

                            break;
                        }
                    default:
                        {
                            // TODO SqlClientX make async request
                            SsrpResult response = SendUDPRequest(ipAddresses, port, requestPacket, true); // allIPsInParallel);
                            if (response != null && response.ResponsePacket != null)
                            {
                                return response.ResponsePacket;
                            }
                            else if (response != null && response.Error != null)
                            {
                                throw response.Error;
                            }

                            break;
                        }
                }

                return null;
            }
        }

        // TODO SqlClientX Make method true async
        /// <summary>
        /// Sends request to server, and receives response from server by UDP.
        /// </summary>
        /// <param name="ipAddresses">IP Addresses</param>
        /// <param name="port">UDP server port</param>
        /// <param name="requestPacket">request packet</param>
        /// <param name="allIPsInParallel">query all resolved IP addresses in parallel</param>
        /// <returns>response packet from UDP server</returns>
        private static SsrpResult SendUDPRequest(IPAddress[] ipAddresses, int port, byte[] requestPacket, bool allIPsInParallel)
        {
            if (ipAddresses.Length == 0)
                return null;

            if (allIPsInParallel) // Used for MultiSubnetFailover
            {
                List<Task<SsrpResult>> tasks = new(ipAddresses.Length);
                CancellationTokenSource cts = new CancellationTokenSource();
                for (int i = 0; i < ipAddresses.Length; i++)
                {
                    IPEndPoint endPoint = new IPEndPoint(ipAddresses[i], port);
                    // TODO SqlClientX make true async request, no sync waits
                    tasks.Add(Task.Factory.StartNew(() => SendUDPRequest(endPoint, requestPacket), cts.Token));
                }

                List<Task<SsrpResult>> completedTasks = new();
                while (tasks.Count > 0)
                {
                    int first = Task.WaitAny(tasks.ToArray());
                    if (tasks[first].Result.ResponsePacket != null)
                    {
                        cts.Cancel();
                        return tasks[first].Result;
                    }
                    else
                    {
                        completedTasks.Add(tasks[first]);
                        tasks.Remove(tasks[first]);
                    }
                }

                Debug.Assert(completedTasks.Count > 0, "completedTasks should never be 0");

                // All tasks failed. Return the error from the first failure.
                return completedTasks[0].Result;
            }
            else
            {
                // If not parallel, use the first IP address provided
                IPEndPoint endPoint = new IPEndPoint(ipAddresses[0], port);
                return SendUDPRequest(endPoint, requestPacket);
            }
        }

        // TODO Make method true async
        private static async SsrpResult SendUDPRequest(IPEndPoint endPoint, byte[] requestPacket, bool async, CancellationToken cancellation)
        {
            const int sendTimeOutMs = 1000;
            const int receiveTimeOutMs = 1000;

            SsrpResult result = new();

            try
            {
                using (UdpClient client = new UdpClient(endPoint.AddressFamily))
                {
                    // TODO SqlClientX make async request, no sync waits
                    Task<int> sendTask = client.SendAsync(requestPacket, requestPacket.Length, endPoint, cancellation);
                    Task<UdpReceiveResult> receiveTask = null;

                    // sync over async - friendly for async operations.
                    sendTask.GetAwaiter().GetResult();

                    // true async
                    await sendTask;

                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SSRP), EventType.INFO, "Waiting for UDP Client to fetch Port info.");
                    if (sendTask.Wait(sendTimeOutMs) && (receiveTask = client.ReceiveAsync()).Wait(receiveTimeOutMs))
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent(nameof(SSRP), EventType.INFO, "Received Port info from UDP Client.");
                        result.ResponsePacket = receiveTask.Result.Buffer;
                    }
                }
            }
            catch (AggregateException ae)
            {
                if (ae.InnerExceptions.Count > 0)
                {
                    // Log all errors
                    foreach (Exception e in ae.InnerExceptions)
                    {
                        // Favor SocketException for returned error
                        if (e is SocketException)
                        {
                            result.Error = e;
                        }
                        SqlClientEventSource.Log.TrySNITraceEvent(nameof(SSRP), EventType.INFO,
                            "SendUDPRequest ({0}) resulted in exception: {1}", args0: endPoint.ToString(), args1: e.Message);
                    }

                    // Return first error if we didn't find a SocketException
                    result.Error = result.Error == null ? ae.InnerExceptions[0] : result.Error;
                }
                else
                {
                    result.Error = ae;
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SSRP), EventType.INFO,
                        "SendUDPRequest ({0}) resulted in exception: {1}", args0: endPoint.ToString(), args1: ae.Message);
                }
            }
            catch (Exception e)
            {
                result.Error = e;
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SSRP), EventType.INFO,
                    "SendUDPRequest ({0}) resulted in exception: {1}", args0: endPoint.ToString(), args1: e.Message);
            }

            return result;
        }

        // TODO Make method truly async
        /// <summary>
        /// Sends request to server, and recieves response from server (SQLBrowser) on port 1434 by UDP
        /// Request (https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/a3035afa-c268-4699-b8fd-4f351e5c8e9e)
        /// Response (https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/2e1560c9-5097-4023-9f5e-72b9ff1ec3b1) 
        /// </summary>
        /// <returns>string constaning list of SVR_RESP(just RESP_DATA)</returns>
        internal static string SendBroadcastUDPRequest()
        {
            StringBuilder response = new StringBuilder();
            byte[] CLNT_BCAST_EX_Request = new byte[1] { Constants.CLNT_BCAST_EX }; //0x02
            // Waits 5 seconds for the first response and every 1 second up to 15 seconds
            // https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/f2640a2d-3beb-464b-a443-f635842ebc3e#Appendix_A_3
            int currentTimeOut = Constants.FirstTimeoutForCLNT_BCAST_EX;

            using (TrySNIEventScope.Create(nameof(SSRP)))
            {
                using (UdpClient clientListener = new UdpClient())
                {
                    Task<int> sendTask = clientListener.SendAsync(CLNT_BCAST_EX_Request, CLNT_BCAST_EX_Request.Length, new IPEndPoint(IPAddress.Broadcast, Constants.SqlServerBrowserPort));
                    Task<UdpReceiveResult> receiveTask = null;
                    SqlClientEventSource.Log.TrySNITraceEvent(nameof(SSRP), EventType.INFO, "Waiting for UDP Client to fetch list of instances.");
                    Stopwatch sw = new Stopwatch(); //for waiting until 15 sec elapsed
                    sw.Start();
                    try
                    {
                        while ((receiveTask = clientListener.ReceiveAsync()).Wait(currentTimeOut) && sw.ElapsedMilliseconds <= Constants.RecieveMAXTimeoutsForCLNT_BCAST_EX && receiveTask != null)
                        {
                            currentTimeOut = Constants.RecieveTimeoutsForCLNT_BCAST_EX;
                            SqlClientEventSource.Log.TrySNITraceEvent(nameof(SSRP), EventType.INFO, "Received instnace info from UDP Client.");
                            if (receiveTask.Result.Buffer.Length < Constants.ValidResponseSizeForCLNT_BCAST_EX) //discard invalid response
                            {
                                response.Append(Encoding.ASCII.GetString(receiveTask.Result.Buffer, Constants.ServerResponseHeaderSizeForCLNT_BCAST_EX, receiveTask.Result.Buffer.Length - Constants.ServerResponseHeaderSizeForCLNT_BCAST_EX)); //RESP_DATA(VARIABLE) - 3 (RESP_SIZE + SVR_RESP)
                            }
                        }
                    }
                    finally
                    {
                        sw.Stop();
                    }
                }
            }
            return response.ToString();
        }

        private static void SplitIPv4AndIPv6(IPAddress[] input, out IPAddress[] ipv4Addresses, out IPAddress[] ipv6Addresses)
        {
            ipv4Addresses = Array.Empty<IPAddress>();
            ipv6Addresses = Array.Empty<IPAddress>();

            if (input != null && input.Length > 0)
            {
                List<IPAddress> v4 = new List<IPAddress>(1);
                List<IPAddress> v6 = new List<IPAddress>(0);

                for (int index = 0; index < input.Length; index++)
                {
                    switch (input[index].AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            v4.Add(input[index]);
                            break;
                        case AddressFamily.InterNetworkV6:
                            v6.Add(input[index]);
                            break;
                    }
                }

                if (v4.Count > 0)
                {
                    ipv4Addresses = v4.ToArray();
                }

                if (v6.Count > 0)
                {
                    ipv6Addresses = v6.ToArray();
                }
            }
        }
        #endregion
    }
}

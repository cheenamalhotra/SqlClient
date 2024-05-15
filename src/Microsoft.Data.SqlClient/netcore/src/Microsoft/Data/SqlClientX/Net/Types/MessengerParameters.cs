// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Data.ProviderBase;
using Microsoft.Data.SqlClient;

namespace Microsoft.Data.SqlClientX.Net.Types
{
    internal class MessengerParameters
    {
        internal readonly string _targetServer;
        internal readonly int _port;
        internal readonly bool _tlsFirst;
        internal readonly string _hostNameInCertificate;
        internal readonly string _serverCertificateFilename;
        internal readonly string _cachedFQDN;
        internal readonly TimeoutTimer _timeout;
        internal readonly SqlConnectionIPAddressPreference _ipAddressPreference;

        internal SqlDnsInfo _pendingDNSInfo;

        public MessengerParameters(string serverName, int port, bool tlsFirst, string hostNameInCertificate, string serverCertificateFilename, string cachedFQDN, TimeoutTimer timeout, SqlDnsInfo pendingDNSInfo, SqlConnectionIPAddressPreference ipPreference)
        {
            _targetServer = serverName;
            _port = port;
            _tlsFirst = tlsFirst;
            _hostNameInCertificate = hostNameInCertificate;
            _serverCertificateFilename = serverCertificateFilename;
            _cachedFQDN = cachedFQDN;
            _timeout = timeout;
            _pendingDNSInfo = pendingDNSInfo;
            _ipAddressPreference = ipPreference;
        }

        public void UpdatePendingDNSInfo(SqlDnsInfo pendingDNSInfo)
        {
            _pendingDNSInfo = pendingDNSInfo;
        }
    }
}

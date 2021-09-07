// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Net;

namespace Microsoft.Data.SqlClient
{
    /// <summary>
    /// Class to pass original client information.
    /// </summary>
#if ADONET_CERT_AUTH
    public 
#else
    internal
#endif
    sealed class SqlClientOriginalNetworkAddressInfo
    {
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientOriginalNetworkAddressInfo.xml' path='docs/members[@name="SqlClientOriginalNetworkAddressInfo"]/ctor/*' />
        public SqlClientOriginalNetworkAddressInfo(IPAddress address, bool isFromDataSecurityProxy = false, bool isVnetAddress = false)
        {
            if (address == null)
            {
                throw new ArgumentNullException("address");
            }

            _address = address;
            _isFromDataSecurityProxy = isFromDataSecurityProxy;
            _isVnetAddress = isVnetAddress;
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientOriginalNetworkAddressInfo.xml' path='docs/members[@name="SqlClientOriginalNetworkAddressInfo"]/GetHashCode/*' />
        public override int GetHashCode()
        {
            return _address != null ? _address.GetHashCode() : 0;
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientOriginalNetworkAddressInfo.xml' path='docs/members[@name="SqlClientOriginalNetworkAddressInfo"]/Equals/*' />
        public override bool Equals(object other)
        {
            SqlClientOriginalNetworkAddressInfo otherAddress = other as SqlClientOriginalNetworkAddressInfo;

            if (otherAddress == null)
            {
                return false;
            }

            if (otherAddress._address != _address)
            {
                return false;
            }

            if (_isFromDataSecurityProxy != otherAddress._isFromDataSecurityProxy)
            {
                return false;
            }

            if (_isVnetAddress != otherAddress._isVnetAddress)
            {
                return false;
            }

            return true;
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientOriginalNetworkAddressInfo.xml' path='docs/members[@name="SqlClientOriginalNetworkAddressInfo"]/Address/*' />
        public IPAddress Address
        {
            get { return _address; }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientOriginalNetworkAddressInfo.xml' path='docs/members[@name="SqlClientOriginalNetworkAddressInfo"]/IsFromDataSecurityProxy/*' />
        public bool IsFromDataSecurityProxy
        {
            get { return _isFromDataSecurityProxy; }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientOriginalNetworkAddressInfo.xml' path='docs/members[@name="SqlClientOriginalNetworkAddressInfo"]/IsVnetAddress/*' />
        public bool IsVnetAddress
        {
            get { return _isVnetAddress; }
        }

        private IPAddress _address;

        private bool _isFromDataSecurityProxy;

        private bool _isVnetAddress;
    }
}


// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace Microsoft.Data.SqlClientX.Net.Helpers
{
    internal static class Constants
    {
        // Each error number maps to SNI_ERROR_* in String.resx
        internal const int ConnTerminatedError = 2;
        internal const int InvalidParameterError = 5;
        internal const int ProtocolNotSupportedError = 8;
        internal const int ConnTimeoutError = 11;
        internal const int ConnNotUsableError = 19;
        internal const int InvalidConnStringError = 25;
        internal const int ErrorLocatingServerInstance = 26;
        internal const int HandshakeFailureError = 31;
        internal const int InternalExceptionError = 35;
        internal const int ConnOpenFailedError = 40;
        internal const int ErrorSpnLookup = 44;
        internal const int LocalDBErrorCode = 50;
        internal const int MultiSubnetFailoverWithMoreThan64IPs = 47;
        internal const int MultiSubnetFailoverWithInstanceSpecified = 48;
        internal const int MultiSubnetFailoverWithNonTcpProtocol = 49;
        internal const int MaxErrorValue = 50157;
        internal const int LocalDBNoInstanceName = 51;
        internal const int LocalDBNoInstallation = 52;
        internal const int LocalDBInvalidConfig = 53;
        internal const int LocalDBNoSqlUserInstanceDllPath = 54;
        internal const int LocalDBInvalidSqlUserInstanceDllPath = 55;
        internal const int LocalDBFailedToLoadDll = 56;
        internal const int LocalDBBadRuntime = 57;

        // Error numbers from native SNI implementation
        internal const uint CertificateValidationErrorCode = 2148074277;

        internal const int SMUX_HEADER_LENGTH = 16;

        // https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/retry-after#simple-retry-for-errors-with-http-error-codes-500-600
        internal const int MsalHttpRetryStatusCode = 429;

        internal const int DefaultSqlServerPort = 1433;
        internal const int DefaultSqlServerDacPort = 1434;
        internal const string SqlServerSpnHeader = "MSSQLSvc";

        // SSRP constants
        internal const char SemicolonSeparator = ';';
        internal const int SqlServerBrowserPort = 1434; //port SQL Server Browser
        internal const int RecieveMAXTimeoutsForCLNT_BCAST_EX = 15000; //Default max time for response wait
        internal const int RecieveTimeoutsForCLNT_BCAST_EX = 1000; //subsequent wait time for response after intial wait 
        internal const int ServerResponseHeaderSizeForCLNT_BCAST_EX = 3;//(SVR_RESP + RESP_SIZE) https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/2e1560c9-5097-4023-9f5e-72b9ff1ec3b1
        internal const int ValidResponseSizeForCLNT_BCAST_EX = 4096; //valid reponse size should be less than 4096
        internal const int FirstTimeoutForCLNT_BCAST_EX = 5000;//wait for first response for 5 seconds
        internal const int CLNT_BCAST_EX = 2;//request packet

    }
}

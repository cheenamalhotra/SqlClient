// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Threading.Tasks;
using Microsoft.Data.SqlClientX.Internal.Connection;
using Microsoft.Data.SqlClientX.Net;
using Microsoft.Data.SqlClientX.Net.Helpers;
using Microsoft.Data.SqlClientX.Net.Security;

namespace Microsoft.Data.SqlClientX.TDS
{
    /// <summary>
    /// This class is designed to provide login capabilities to a SqlInternalConnection instance.
    /// There 1 public API for this class:
    ///       ConnectAsync()
    ///         Performs all operations for connection establishment.
    ///             Prelogin, Login, Messenger creation, etc.
    ///         returns SqlConnectionStateInfo that can be updated on the SqlInternalConnection instance by the caller.
    ///         
    /// Things to do:
    ///     1. Design method APIs to be trly async, to accept 'async' and 'cancellationToken'
    ///     2. Minimize params, push to SqlConnectionStateInfo if possible.
    /// </summary>
    internal class LoginHandler
    {
        #region Public APIs

        /// <summary>
        /// Establish connection with server
        /// </summary>
        /// <param name="serverInfo"></param>
        /// <param name="connHandler"></param>
        /// <param name="timeout"></param>
        /// <param name="connectionOptions"></param>
        /// <param name="withFailover"></param>
        /// <returns></returns>
        public async Task<SqlConnectionStateInfo> ConnectAsync(
            ServerInfo serverInfo,
            SqlConnectionStateInfo connHandler,
            TimeoutTimer timeout,
            SqlConnectionString connectionOptions,
            bool withFailover)
        {
            SqlConnectionEncryptOption encrypt = connectionOptions.Encrypt;
            bool isTlsFirst = encrypt == SqlConnectionEncryptOption.Strict;
            bool trustServerCert = connectionOptions.TrustServerCertificate;
            bool integratedSecurity = connectionOptions.IntegratedSecurity;
            SqlAuthenticationMethod authType = connectionOptions.Authentication;
            string hostNameInCertificate = connectionOptions.HostNameInCertificate;
            string serverCertificateFilename = connectionOptions.ServerCertificate;

            if (_state != TdsParserState.Closed)
            {
                Debug.Fail("TdsParser.Connect called on non-closed connection!");
                return;
            }

            // _connHandler = connHandler;
            _loginWithFailover = withFailover;

            // Clean up IsSQLDNSCachingSupported flag from previous status
            connHandler.IsSQLDNSCachingSupported = false;

            uint sniStatus = TdsParserStateObjectFactory.Singleton.SNIStatus;

            if (sniStatus != TdsEnums.SNI_SUCCESS)
            {
                _physicalStateObj.AddError(ProcessSNIError(_physicalStateObj));
                _physicalStateObj.Dispose();
                ThrowExceptionAndWarning(_physicalStateObj);
                Debug.Fail("SNI returned status != success, but no error thrown?");
            }
            else
            {
                _sniSpnBuffer = null;
                SqlClientEventSource.Log.TryTraceEvent("TdsParser.Connect | SEC | Connection Object Id {0}, Authentication Mode: {1}", _connHandler._objectID,
                    authType == SqlAuthenticationMethod.NotSpecified ? SqlAuthenticationMethod.SqlPassword.ToString() : authType.ToString());
            }

            // Encryption is not supported on SQL Local DB - disable it if they have only specified Mandatory
            if (connHandler.ConnectionOptions.LocalDBInstance != null && encrypt == SqlConnectionEncryptOption.Mandatory)
            {
                encrypt = SqlConnectionEncryptOption.Optional;
                SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|SEC> Encryption will be disabled as target server is a SQL Local DB instance.");
            }

            _sniSpnBuffer = null;
            _authenticationProvider = null;

            // AD Integrated behaves like Windows integrated when connecting to a non-fedAuth server
            if (integratedSecurity || authType == SqlAuthenticationMethod.ActiveDirectoryIntegrated)
            {
                _authenticationProvider = CreateSSPIContextProvider();
                SqlClientEventSource.Log.TryTraceEvent("TdsParser.Connect | SEC | SSPI or Active Directory Authentication Library loaded for SQL Server based integrated authentication");
            }

            // if Strict encryption (i.e. isTlsFirst) is chosen trust server certificate should always be false.
            if (isTlsFirst)
            {
                trustServerCert = false;
            }

            byte[] instanceName = null;

            Debug.Assert(connHandler != null, "SqlConnectionInternalTds handler can not be null at this point.");
            connHandler.TimeoutErrorInternal.EndPhase(SqlConnectionTimeoutErrorPhase.PreLoginBegin);
            connHandler.TimeoutErrorInternal.SetAndBeginPhase(SqlConnectionTimeoutErrorPhase.InitializeConnection);

            bool fParallel = connHandler.ConnectionOptions.MultiSubnetFailover;

            FQDNforDNSCache = serverInfo.ResolvedServerName;

            int commaPos = FQDNforDNSCache.IndexOf(",", StringComparison.Ordinal);
            if (commaPos != -1)
            {
                FQDNforDNSCache = FQDNforDNSCache.Substring(0, commaPos);
            }

            connHandler.pendingSQLDNSObject = null;

            // AD Integrated behaves like Windows integrated when connecting to a non-fedAuth server
            await CreatePhysicalMessengerAsync(
                serverInfo.ExtendedServerName,
                timeout,
                out instanceName,
                ref _sniSpnBuffer,
                false,
                true,
                fParallel,
                connHandler.ConnectionOptions.IPAddressPreference,
                FQDNforDNSCache,
                ref connHandler.pendingSQLDNSObject,
                serverInfo.ServerSPN,
                integratedSecurity || authType == SqlAuthenticationMethod.ActiveDirectoryIntegrated,
                isTlsFirst,
                hostNameInCertificate,
                serverCertificateFilename);

            _authenticationProvider?.Initialize(serverInfo, _physicalStateObj, this);

            if (TdsEnums.SNI_SUCCESS != _physicalStateObj.Status)
            {
                _physicalStateObj.AddError(ProcessSNIError(_physicalStateObj));

                // Since connect failed, free the unmanaged connection memory.
                // HOWEVER - only free this after the netlib error was processed - if you
                // don't, the memory for the connection object might not be accurate and thus
                // a bad error could be returned (as it was when it was freed to early for me).
                _physicalStateObj.Dispose();
                SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|ERR|SEC> Login failure");
                ThrowExceptionAndWarning(_physicalStateObj);
                Debug.Fail("SNI returned status != success, but no error thrown?");
            }

            _server = serverInfo.ResolvedServerName;

            if (null != connHandler.PoolGroupProviderInfo)
            {
                // If we are pooling, check to see if we were processing an
                // alias which has changed, which means we need to clean out
                // the pool. See Webdata 104293.
                // This should not apply to routing, as it is not an alias change, routed connection
                // should still use VNN of AlwaysOn cluster as server for pooling purposes.
                connHandler.PoolGroupProviderInfo.AliasCheck(serverInfo.PreRoutingServerName == null ?
                    serverInfo.ResolvedServerName : serverInfo.PreRoutingServerName);
            }
            _state = TdsParserState.OpenNotLoggedIn;
            _physicalStateObj.SniContext = SniContext.Snix_PreLoginBeforeSuccessfulWrite;
            _physicalStateObj.TimeoutTime = timeout.LegacyTimerExpire;

            bool marsCapable = false;

            connHandler.TimeoutErrorInternal.EndPhase(SqlConnectionTimeoutErrorPhase.InitializeConnection);
            connHandler.TimeoutErrorInternal.SetAndBeginPhase(SqlConnectionTimeoutErrorPhase.SendPreLoginHandshake);

            uint result = _physicalStateObj.SniGetConnectionId(ref _connHandler._clientConnectionId);
            Debug.Assert(result == TdsEnums.SNI_SUCCESS, "Unexpected failure state upon calling SniGetConnectionId");

            if (null == _connHandler.pendingSQLDNSObject)
            {
                // for DNS Caching phase 1
                _physicalStateObj.AssignPendingDNSInfo(serverInfo.UserProtocol, FQDNforDNSCache, ref _connHandler.pendingSQLDNSObject);
            }

            if (!ClientOSEncryptionSupport)
            {
                //If encryption is required, an error will be thrown.
                if (encrypt != SqlConnectionEncryptOption.Optional)
                {
                    _physicalStateObj.AddError(new SqlError(TdsEnums.ENCRYPTION_NOT_SUPPORTED, (byte)0x00, TdsEnums.FATAL_ERROR_CLASS, _server, SQLMessage.EncryptionNotSupportedByClient(), "", 0));
                    _physicalStateObj.Dispose();
                    ThrowExceptionAndWarning(_physicalStateObj);
                }
                _encryptionOption = EncryptionOptions.NOT_SUP;
            }

            SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|SEC> Sending prelogin handshake");
            SendPreLoginHandshake(instanceName, encrypt, integratedSecurity, serverCertificateFilename);

            connHandler.TimeoutErrorInternal.EndPhase(SqlConnectionTimeoutErrorPhase.SendPreLoginHandshake);
            connHandler.TimeoutErrorInternal.SetAndBeginPhase(SqlConnectionTimeoutErrorPhase.ConsumePreLoginHandshake);

            _physicalStateObj.SniContext = SniContext.Snix_PreLogin;
            SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|SEC> Consuming prelogin handshake");
            PreLoginHandshakeStatus status = ConsumePreLoginHandshake(
                encrypt,
                trustServerCert,
                integratedSecurity,
                out marsCapable,
                out _connHandler._fedAuthRequired,
                isTlsFirst,
                serverCertificateFilename);

            if (status == PreLoginHandshakeStatus.InstanceFailure)
            {
                SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|SEC> Prelogin handshake unsuccessful. Reattempting prelogin handshake");
                _physicalStateObj.Dispose(); // Close previous connection

                // On Instance failure re-connect and flush SNI named instance cache.
                _physicalStateObj.SniContext = SniContext.Snix_Connect;

                await CreatePhysicalMessengerAsync(
                    serverInfo.ExtendedServerName,
                    timeout, out instanceName,
                    ref _sniSpnBuffer,
                    true,
                    true,
                    fParallel,
                    _connHandler.ConnectionOptions.IPAddressPreference,
                    FQDNforDNSCache,
                    ref _connHandler.pendingSQLDNSObject,
                    serverInfo.ServerSPN,
                    integratedSecurity,
                    isTlsFirst,
                    hostNameInCertificate,
                    serverCertificateFilename);

                _authenticationProvider?.Initialize(serverInfo, _physicalStateObj, this);

                if (TdsEnums.SNI_SUCCESS != _physicalStateObj.Status)
                {
                    _physicalStateObj.AddError(ProcessSNIError(_physicalStateObj));
                    SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|ERR|SEC> Login failure");
                    ThrowExceptionAndWarning(_physicalStateObj);
                }

                uint retCode = _physicalStateObj.SniGetConnectionId(ref _connHandler._clientConnectionId);

                Debug.Assert(retCode == TdsEnums.SNI_SUCCESS, "Unexpected failure state upon calling SniGetConnectionId");
                SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|SEC> Sending prelogin handshake");

                if (null == _connHandler.pendingSQLDNSObject)
                {
                    // for DNS Caching phase 1
                    _physicalStateObj.AssignPendingDNSInfo(serverInfo.UserProtocol, FQDNforDNSCache, ref _connHandler.pendingSQLDNSObject);
                }

                await SendPreLoginHandshakeAsync(instanceName, encrypt, integratedSecurity, serverCertificateFilename);
                status = await ConsumePreLoginHandshakeAsync(
                    encrypt,
                    trustServerCert,
                    integratedSecurity,
                    out marsCapable,
                    out _connHandler._fedAuthRequired,
                    isTlsFirst,
                    serverCertificateFilename);

                // Don't need to check for 7.0 failure, since we've already consumed
                // one pre-login packet and know we are connecting to 2000.
                if (status == PreLoginHandshakeStatus.InstanceFailure)
                {
                    SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|ERR|SEC> Prelogin handshake unsuccessful. Login failure");
                    throw SQL.InstanceFailure();
                }
            }
            SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Connect|SEC> Prelogin handshake successful");

            if (_fMARS && marsCapable)
            {
                // if user explicitly disables mars or mars not supported, don't create the session pool
                _sessionPool = new TdsParserSessionPool(this);
            }
            else
            {
                _fMARS = false;
            }
            return;
        }

        #endregion

        #region Private Helpers

        private async Task SendPreLoginHandshakeAsync(
            byte[] instanceName,
            SqlConnectionEncryptOption encrypt,
            bool integratedSecurity,
            string serverCertificateFilename)
        {
            if (encrypt == SqlConnectionEncryptOption.Strict)
            {
                //Always validate the certificate when in strict encryption mode
                uint info = TdsEnums.SNI_SSL_VALIDATE_CERTIFICATE | TdsEnums.SNI_SSL_USE_SCHANNEL_CACHE | TdsEnums.SNI_SSL_SEND_ALPN_EXTENSION;

                await EnableSslAsync(info, encrypt, integratedSecurity, serverCertificateFilename);

                // Since encryption has already been negotiated, we need to set encryption not supported in
                // prelogin so that we don't try to negotiate encryption again during ConsumePreLoginHandshake.
                _encryptionOption = EncryptionOptions.NOT_SUP;
            }

            // PreLoginHandshake buffer consists of:
            // 1) Standard header, with type = MT_PRELOGIN
            // 2) Consecutive 5 bytes for each option, (1 byte length, 2 byte offset, 2 byte payload length)
            // 3) Consecutive data blocks for each option

            // NOTE: packet data needs to be big endian - not the standard little endian used by
            // the rest of the parser.

            _physicalStateObj._outputMessageType = TdsEnums.MT_PRELOGIN;

            // Initialize option offset into payload buffer
            // 5 bytes for each option (1 byte length, 2 byte offset, 2 byte payload length)
            int offset = (int)PreLoginOptions.NUMOPT * 5 + 1;

            byte[] payload = new byte[(int)PreLoginOptions.NUMOPT * 5 + TdsEnums.MAX_PRELOGIN_PAYLOAD_LENGTH];
            int payloadLength = 0;

            for (int option = (int)PreLoginOptions.VERSION; option < (int)PreLoginOptions.NUMOPT; option++)
            {
                int optionDataSize = 0;

                // Fill in the option
                _physicalStateObj.WriteByte((byte)option);

                // Fill in the offset of the option data
                _physicalStateObj.WriteByte((byte)((offset & 0xff00) >> 8)); // send upper order byte
                _physicalStateObj.WriteByte((byte)(offset & 0x00ff)); // send lower order byte

                switch (option)
                {
                    case (int)PreLoginOptions.VERSION:
                        Version systemDataVersion = ADP.GetAssemblyVersion();

                        // Major and minor
                        payload[payloadLength++] = (byte)(systemDataVersion.Major & 0xff);
                        payload[payloadLength++] = (byte)(systemDataVersion.Minor & 0xff);

                        // Build (Big Endian)
                        payload[payloadLength++] = (byte)((systemDataVersion.Build & 0xff00) >> 8);
                        payload[payloadLength++] = (byte)(systemDataVersion.Build & 0xff);

                        // Sub-build (Little Endian)
                        payload[payloadLength++] = (byte)(systemDataVersion.Revision & 0xff);
                        payload[payloadLength++] = (byte)((systemDataVersion.Revision & 0xff00) >> 8);
                        offset += 6;
                        optionDataSize = 6;
                        break;

                    case (int)PreLoginOptions.ENCRYPT:
                        if (_encryptionOption == EncryptionOptions.NOT_SUP)
                        {
                            //If OS doesn't support encryption and encryption is not required, inform server "not supported" by client.
                            payload[payloadLength] = (byte)EncryptionOptions.NOT_SUP;
                        }
                        else
                        {
                            // Else, inform server of user request.
                            if (encrypt == SqlConnectionEncryptOption.Mandatory)
                            {
                                payload[payloadLength] = (byte)EncryptionOptions.ON;
                                _encryptionOption = EncryptionOptions.ON;
                            }
                            else
                            {
                                payload[payloadLength] = (byte)EncryptionOptions.OFF;
                                _encryptionOption = EncryptionOptions.OFF;
                            }
                        }

                        payloadLength += 1;
                        offset += 1;
                        optionDataSize = 1;
                        break;

                    case (int)PreLoginOptions.INSTANCE:
                        int i = 0;

                        while (instanceName[i] != 0)
                        {
                            payload[payloadLength] = instanceName[i];
                            payloadLength++;
                            i++;
                        }

                        payload[payloadLength] = 0; // null terminate
                        payloadLength++;
                        i++;

                        offset += i;
                        optionDataSize = i;
                        break;

                    case (int)PreLoginOptions.THREADID:
                        int threadID = TdsParserStaticMethods.GetCurrentThreadIdForTdsLoginOnly();

                        payload[payloadLength++] = (byte)((0xff000000 & threadID) >> 24);
                        payload[payloadLength++] = (byte)((0x00ff0000 & threadID) >> 16);
                        payload[payloadLength++] = (byte)((0x0000ff00 & threadID) >> 8);
                        payload[payloadLength++] = (byte)(0x000000ff & threadID);
                        offset += 4;
                        optionDataSize = 4;
                        break;

                    case (int)PreLoginOptions.MARS:
                        payload[payloadLength++] = (byte)(_fMARS ? 1 : 0);
                        offset += 1;
                        optionDataSize += 1;
                        break;

                    case (int)PreLoginOptions.TRACEID:
                        FillGuidBytes(_connHandler._clientConnectionId, payload.AsSpan(payloadLength, GUID_SIZE));
                        payloadLength += GUID_SIZE;
                        offset += GUID_SIZE;
                        optionDataSize = GUID_SIZE;

                        ActivityCorrelator.ActivityId actId = ActivityCorrelator.Next();
                        FillGuidBytes(actId.Id, payload.AsSpan(payloadLength, GUID_SIZE));
                        payloadLength += GUID_SIZE;
                        payload[payloadLength++] = (byte)(0x000000ff & actId.Sequence);
                        payload[payloadLength++] = (byte)((0x0000ff00 & actId.Sequence) >> 8);
                        payload[payloadLength++] = (byte)((0x00ff0000 & actId.Sequence) >> 16);
                        payload[payloadLength++] = (byte)((0xff000000 & actId.Sequence) >> 24);
                        int actIdSize = GUID_SIZE + sizeof(uint);
                        offset += actIdSize;
                        optionDataSize += actIdSize;
                        SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.SendPreLoginHandshake|INFO> ClientConnectionID {0}, ActivityID {1}", _connHandler?._clientConnectionId, actId);
                        break;

                    case (int)PreLoginOptions.FEDAUTHREQUIRED:
                        payload[payloadLength++] = 0x01;
                        offset += 1;
                        optionDataSize += 1;
                        break;

                    default:
                        Debug.Fail("UNKNOWN option in SendPreLoginHandshake");
                        break;
                }

                // Write data length
                _physicalStateObj.WriteByte((byte)((optionDataSize & 0xff00) >> 8));
                _physicalStateObj.WriteByte((byte)(optionDataSize & 0x00ff));
            }

            // Write out last option - to let server know the second part of packet completed
            _physicalStateObj.WriteByte((byte)PreLoginOptions.LASTOPT);

            // Write out payload
            _physicalStateObj.WriteByteArray(payload, payloadLength, 0);

            // Flush packet
            _physicalStateObj.WritePacket(TdsEnums.HARDFLUSH);
        }

        private async Task EnableSslAsync(uint info, SqlConnectionEncryptOption encrypt, bool integratedSecurity, string serverCertificateFilename)
        {
            uint error = 0;

            if (encrypt && !integratedSecurity)
            {
                // optimization: in case of SQL Authentication and encryption in TDS, set SNI_SSL_IGNORE_CHANNEL_BINDINGS
                // to let SNI know that it does not need to allocate/retrieve the Channel Bindings from the SSL context.
                // This applies to Native SNI
                info |= TdsEnums.SNI_SSL_IGNORE_CHANNEL_BINDINGS;
            }

            error = _physicalStateObj.EnableSsl(ref info, encrypt == SqlConnectionEncryptOption.Strict, serverCertificateFilename);

            if (error != TdsEnums.SNI_SUCCESS)
            {
                _physicalStateObj.AddError(ProcessSNIError(_physicalStateObj));
                ThrowExceptionAndWarning(_physicalStateObj);
            }

            int protocolVersion = 0;
            WaitForSSLHandShakeToComplete(ref error, ref protocolVersion);

            SslProtocols protocol = (SslProtocols)protocolVersion;
            string warningMessage = protocol.GetProtocolWarning();
            if (!string.IsNullOrEmpty(warningMessage))
            {
                if (!encrypt && LocalAppContextSwitches.SuppressInsecureTLSWarning)
                {
                    // Skip console warning
                    SqlClientEventSource.Log.TryTraceEvent("<sc|{0}|{1}|{2}>{3}", nameof(TdsParser), nameof(EnableSsl), SqlClientLogger.LogLevel.Warning, warningMessage);
                }
                else
                {
                    // This logs console warning of insecure protocol in use.
                    _logger.LogWarning(nameof(TdsParser), nameof(EnableSsl), warningMessage);
                }
            }

            // create a new packet encryption changes the internal packet size
            _physicalStateObj.ClearAllWritePackets();
        }

        private async Task<PreLoginHandshakeStatus> ConsumePreLoginHandshakeAsync(
            SqlConnectionEncryptOption encrypt,
            bool trustServerCert,
            bool integratedSecurity,
            out bool marsCapable,
            out bool fedAuthRequired,
            bool tlsFirst,
            string serverCert)
        {
            marsCapable = _fMARS; // Assign default value
            fedAuthRequired = false;
            bool is2005OrLater = false;
            Debug.Assert(_physicalStateObj._syncOverAsync, "Should not attempt pends in a synchronous call");
            bool result = _physicalStateObj.TryReadNetworkPacket();
            if (!result)
            {
                throw SQL.SynchronousCallMayNotPend();
            }

            if (_physicalStateObj._inBytesRead == 0)
            {
                // If the server did not respond then something has gone wrong and we need to close the connection
                _physicalStateObj.AddError(new SqlError(0, (byte)0x00, TdsEnums.FATAL_ERROR_CLASS, _server, SQLMessage.PreloginError(), "", 0));
                _physicalStateObj.Dispose();
                ThrowExceptionAndWarning(_physicalStateObj);
            }

            if (!_physicalStateObj.TryProcessHeader())
            {
                throw SQL.SynchronousCallMayNotPend();
            }

            if (_physicalStateObj._inBytesPacket > TdsEnums.MAX_PACKET_SIZE || _physicalStateObj._inBytesPacket <= 0)
            {
                throw SQL.ParsingError();
            }
            byte[] payload = new byte[_physicalStateObj._inBytesPacket];

            Debug.Assert(_physicalStateObj._syncOverAsync, "Should not attempt pends in a synchronous call");
            result = _physicalStateObj.TryReadByteArray(payload, payload.Length);
            if (!result)
            {
                throw SQL.SynchronousCallMayNotPend();
            }

            if (payload[0] == 0xaa)
            {
                // If the first byte is 0xAA, we are connecting to a 6.5 or earlier server, which
                // is not supported.
                throw SQL.InvalidSQLServerVersionUnknown();
            }

            int offset = 0;
            int payloadOffset = 0;
            int payloadLength = 0;
            int option = payload[offset++];
            bool serverSupportsEncryption = false;

            while (option != (byte)PreLoginOptions.LASTOPT)
            {
                switch (option)
                {
                    case (int)PreLoginOptions.VERSION:
                        payloadOffset = payload[offset++] << 8 | payload[offset++];
                        payloadLength = payload[offset++] << 8 | payload[offset++];

                        byte majorVersion = payload[payloadOffset];
                        byte minorVersion = payload[payloadOffset + 1];
                        int level = payload[payloadOffset + 2] << 8 |
                                             payload[payloadOffset + 3];

                        is2005OrLater = majorVersion >= 9;
                        if (!is2005OrLater)
                        {
                            marsCapable = false;            // If pre-2005, MARS not supported.
                        }

                        break;

                    case (int)PreLoginOptions.ENCRYPT:
                        if (tlsFirst)
                        {
                            // Can skip/ignore this option if we are doing TDS 8.
                            offset += 4;
                            break;
                        }

                        payloadOffset = payload[offset++] << 8 | payload[offset++];
                        payloadLength = payload[offset++] << 8 | payload[offset++];

                        EncryptionOptions serverOption = (EncryptionOptions)payload[payloadOffset];

                        /* internal enum EncryptionOptions {
                            OFF,
                            ON,
                            NOT_SUP,
                            REQ,
                            LOGIN
                        } */

                        // Any response other than NOT_SUP means the server supports encryption.
                        serverSupportsEncryption = serverOption != EncryptionOptions.NOT_SUP;

                        switch (_encryptionOption)
                        {
                            case EncryptionOptions.OFF:
                                if (serverOption == EncryptionOptions.OFF)
                                {
                                    // Only encrypt login.
                                    _encryptionOption = EncryptionOptions.LOGIN;
                                }
                                else if (serverOption == EncryptionOptions.REQ)
                                {
                                    // Encrypt all.
                                    _encryptionOption = EncryptionOptions.ON;
                                }
                                // NOT_SUP: No encryption.
                                break;

                            case EncryptionOptions.NOT_SUP:
                                if (serverOption == EncryptionOptions.REQ)
                                {
                                    // Server requires encryption, but client does not support it.
                                    _physicalStateObj.AddError(new SqlError(TdsEnums.ENCRYPTION_NOT_SUPPORTED, (byte)0x00, TdsEnums.FATAL_ERROR_CLASS, _server, SQLMessage.EncryptionNotSupportedByClient(), "", 0));
                                    _physicalStateObj.Dispose();
                                    ThrowExceptionAndWarning(_physicalStateObj);
                                }

                                break;
                            default:
                                // Any other client option needs encryption
                                if (serverOption == EncryptionOptions.NOT_SUP)
                                {
                                    _physicalStateObj.AddError(new SqlError(TdsEnums.ENCRYPTION_NOT_SUPPORTED, (byte)0x00, TdsEnums.FATAL_ERROR_CLASS, _server, SQLMessage.EncryptionNotSupportedByServer(), "", 0));
                                    _physicalStateObj.Dispose();
                                    ThrowExceptionAndWarning(_physicalStateObj);
                                }
                                break;
                        }

                        break;

                    case (int)PreLoginOptions.INSTANCE:
                        payloadOffset = payload[offset++] << 8 | payload[offset++];
                        payloadLength = payload[offset++] << 8 | payload[offset++];

                        byte ERROR_INST = 0x1;
                        byte instanceResult = payload[payloadOffset];

                        if (instanceResult == ERROR_INST)
                        {
                            // Check if server says ERROR_INST. That either means the cached info
                            // we used to connect is not valid or we connected to a named instance
                            // listening on default params.
                            return PreLoginHandshakeStatus.InstanceFailure;
                        }

                        break;

                    case (int)PreLoginOptions.THREADID:
                        // DO NOTHING FOR THREADID
                        offset += 4;
                        break;

                    case (int)PreLoginOptions.MARS:
                        payloadOffset = payload[offset++] << 8 | payload[offset++];
                        payloadLength = payload[offset++] << 8 | payload[offset++];

                        marsCapable = payload[payloadOffset] == 0 ? false : true;

                        Debug.Assert(payload[payloadOffset] == 0 || payload[payloadOffset] == 1, "Value for Mars PreLoginHandshake option not equal to 1 or 0!");
                        break;

                    case (int)PreLoginOptions.TRACEID:
                        // DO NOTHING FOR TRACEID
                        offset += 4;
                        break;

                    case (int)PreLoginOptions.FEDAUTHREQUIRED:
                        payloadOffset = payload[offset++] << 8 | payload[offset++];
                        payloadLength = payload[offset++] << 8 | payload[offset++];

                        // Only 0x00 and 0x01 are accepted values from the server.
                        if (payload[payloadOffset] != 0x00 && payload[payloadOffset] != 0x01)
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.ConsumePreLoginHandshake|ERR> {0}, " +
                                "Server sent an unexpected value for FedAuthRequired PreLogin Option. Value was {1}.", ObjectID, (int)payload[payloadOffset]);
                            throw SQL.ParsingErrorValue(ParsingErrorState.FedAuthRequiredPreLoginResponseInvalidValue, payload[payloadOffset]);
                        }

                        // We must NOT use the response for the FEDAUTHREQUIRED PreLogin option, if the connection string option
                        // was not using the new Authentication keyword or in other words, if Authentication=NotSpecified
                        // Or AccessToken is not null, mean token based authentication is used.
                        if (_connHandler.ConnectionOptions != null
                            && _connHandler.ConnectionOptions.Authentication != SqlAuthenticationMethod.NotSpecified
                            || _connHandler._accessTokenInBytes != null || _connHandler._accessTokenCallback != null)
                        {
                            fedAuthRequired = payload[payloadOffset] == 0x01 ? true : false;
                        }
                        break;

                    default:
                        Debug.Fail("UNKNOWN option in ConsumePreLoginHandshake, option:" + option);

                        // DO NOTHING FOR THESE UNKNOWN OPTIONS
                        offset += 4;

                        break;
                }

                if (offset < payload.Length)
                {
                    option = payload[offset++];
                }
                else
                {
                    break;
                }
            }

            if (_encryptionOption == EncryptionOptions.ON ||
                _encryptionOption == EncryptionOptions.LOGIN)
            {
                if (!serverSupportsEncryption)
                {
                    _physicalStateObj.AddError(new SqlError(TdsEnums.ENCRYPTION_NOT_SUPPORTED, (byte)0x00, TdsEnums.FATAL_ERROR_CLASS, _server, SQLMessage.EncryptionNotSupportedByServer(), "", 0));
                    _physicalStateObj.Dispose();
                    ThrowExceptionAndWarning(_physicalStateObj);
                }

                // Validate Certificate if Trust Server Certificate=false and Encryption forced (EncryptionOptions.ON) from Server.
                bool shouldValidateServerCert = _encryptionOption == EncryptionOptions.ON && !trustServerCert ||
                    _connHandler._accessTokenInBytes != null && !trustServerCert;
                uint info = (shouldValidateServerCert ? TdsEnums.SNI_SSL_VALIDATE_CERTIFICATE : 0)
                    | (is2005OrLater ? TdsEnums.SNI_SSL_USE_SCHANNEL_CACHE : 0);

                EnableSsl(info, encrypt, integratedSecurity, serverCert);
            }

            return PreLoginHandshakeStatus.Successful;
        }


        private SSPIContextProvider CreateSSPIContextProvider()
#if NET8_0_OR_GREATER
            => new NegotiateSSPIContextProvider();
#else
            => new SspiClientContextProvider();
#endif

        // TODO return messenger result
        private async Task<Messenger> CreatePhysicalMessengerAsync(
            string serverName,
            TimeoutTimer timeout,
            out byte[] instanceName,
            ref byte[][] spnBuffer,
            bool flushCache,
            bool async,
            bool parallel,
            SqlConnectionIPAddressPreference iPAddressPreference,
            string cachedFQDN,
            ref SqlDnsInfo pendingDNSInfo,
            string serverSPN,
            bool isIntegratedSecurity,
            bool tlsFirst,
            string hostNameInCertificate,
            string serverCertificateFilename)
        {
            Messenger messenger = await NetworkUtil.CreateMessengerAsync(serverName, timeout, out instanceName, ref spnBuffer, serverSPN,
                flushCache, async, parallel, isIntegratedSecurity, iPAddressPreference, cachedFQDN, ref pendingDNSInfo, tlsFirst,
                hostNameInCertificate, serverCertificateFilename);

            if (messenger is not null)
            {
                SqlClientEventSource.Log.TryTraceEvent("LoginProvider.CreatePhysicalMessengerAsync | Info | State Object Id {0}, Session Id {1}, ServerName {2}, Async = {3}", _objectID, messenger.ConnectionId, serverName, async);
                if (async)
                {
                    // TODO Create call backs and allocate to the session handle
                    messenger.SetAsyncCallbacks(ReadAsyncCallback, WriteAsyncCallback);
                }
            }
            else
            {
                _parser.ProcessSNIError(this);
            }

            return messenger;
        }

        #endregion
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET8_0_OR_GREATER

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClient.DataClassification;
using Microsoft.Data.SqlClientX.IO;
using Microsoft.Data.SqlClientX.Tds.State;

namespace Microsoft.Data.SqlClientX.Tds
{
    internal static class TdsParserExtensions
    {
        public static async ValueTask ProcessFeatureExtAsync(this TdsParserX parser, bool isAsync, CancellationToken ct)
        {
            TdsReader reader = parser..TdsStream.TdsReader;
            // read feature ID
            byte featureId;
            do
            {
                featureId = await reader.ReadByteAsync(isAsync, ct).ConfigureAwait(false);
                if (featureId != TdsEnums.FEATUREEXT_TERMINATOR)
                {
                    uint dataLen = await reader.ReadUInt32Async(isAsync, ct).ConfigureAwait(false);
                    Memory<byte> data = new byte[dataLen];
                    if (dataLen > 0)
                    {
                        await reader.ReadBytesAsync(data, isAsync, ct).ConfigureAwait(false);
                    }
                    parser.TdsContext.OnFeatureExtAck(featureId, data);
                }
            } while (featureId != TdsEnums.FEATUREEXT_TERMINATOR);

            // Write to DNS Cache or clean up DNS Cache for TCP protocol
            bool ret = false;
            if (parser.TdsContext.SqlConnector._cleanSQLDNSCaching)
            {
                ret = SQLFallbackDNSCache.Instance.DeleteDNSInfo(FQDNforDNSCache);
            }

            if (_connHandler.IsSQLDNSCachingSupported && _connHandler.pendingSQLDNSObject != null
                    && !SQLFallbackDNSCache.Instance.IsDuplicate(_connHandler.pendingSQLDNSObject))
            {
                ret = SQLFallbackDNSCache.Instance.AddDNSInfo(_connHandler.pendingSQLDNSObject);
                _connHandler.pendingSQLDNSObject = null;
            }

            // Check if column encryption was on and feature wasn't acknowledged and we aren't going to be routed to another server.
            if (Connection.RoutingInfo == null
                && _connHandler.ConnectionOptions.ColumnEncryptionSetting == SqlConnectionColumnEncryptionSetting.Enabled
                && !IsColumnEncryptionSupported)
            {
                throw SQL.TceNotSupported();
            }

            // Check if server does not support Enclave Computations and we aren't going to be routed to another server.
            if (Connection.RoutingInfo == null)
            {
                SqlConnectionAttestationProtocol attestationProtocol = _connHandler.ConnectionOptions.AttestationProtocol;

                if (TceVersionSupported < TdsEnums.MIN_TCE_VERSION_WITH_ENCLAVE_SUPPORT)
                {
                    // Check if enclave attestation url was specified and server does not support enclave computations and we aren't going to be routed to another server.
                    if (!string.IsNullOrWhiteSpace(_connHandler.ConnectionOptions.EnclaveAttestationUrl) && attestationProtocol != SqlConnectionAttestationProtocol.NotSpecified)
                    {
                        throw SQL.EnclaveComputationsNotSupported();
                    }
                    else if (!string.IsNullOrWhiteSpace(_connHandler.ConnectionOptions.EnclaveAttestationUrl))
                    {
                        throw SQL.AttestationURLNotSupported();
                    }
                    else if (_connHandler.ConnectionOptions.AttestationProtocol != SqlConnectionAttestationProtocol.NotSpecified)
                    {
                        throw SQL.AttestationProtocolNotSupported();
                    }
                }

                // Check if enclave attestation url was specified and server does not return an enclave type and we aren't going to be routed to another server.
                if (!string.IsNullOrWhiteSpace(_connHandler.ConnectionOptions.EnclaveAttestationUrl) || attestationProtocol == SqlConnectionAttestationProtocol.None)
                {
                    if (string.IsNullOrWhiteSpace(TdsContext.EnclaveType))
                    {
                        throw SQL.EnclaveTypeNotReturned();
                    }
                    else
                    {
                        // Check if the attestation protocol is specified and supports the enclave type.
                        if (SqlConnectionAttestationProtocol.NotSpecified != attestationProtocol && !TdsUtils.IsValidAttestationProtocol(attestationProtocol, EnclaveType))
                        {
                            throw SQL.AttestationProtocolNotSupportEnclaveType(attestationProtocol.ToString(), EnclaveType);
                        }
                    }
                }
            }
        }

        internal static void OnFeatureExtAck(this TdsContext context, int featureId, Memory<byte> data)
        {
            if (context.ConnectionState.RoutingInfo != null && TdsEnums.FEATUREEXT_SQLDNSCACHING != featureId)
            {
                return;
            }

            switch (featureId)
            {
                case TdsEnums.FEATUREEXT_SRECOVERY:
                    {
                        // Session recovery not requested
                        if (!_sessionRecoveryRequested)
                        {
                            throw SQL.ParsingError();
                        }
                        _sessionRecoveryAcknowledged = true;

#if DEBUG
                        foreach (var s in _currentSessionData._delta)
                        {
                            Debug.Assert(s == null, "Delta should be null at this point");
                        }
#endif
                        Debug.Assert(_currentSessionData._unrecoverableStatesCount == 0, "Unrecoverable states count should be 0");

                        int i = 0;
                        while (i < data.Length)
                        {
                            byte stateId = data[i];
                            i++;
                            int len;
                            byte bLen = data[i];
                            i++;
                            if (bLen == 0xFF)
                            {
                                len = BitConverter.ToInt32(data, i);
                                i += 4;
                            }
                            else
                            {
                                len = bLen;
                            }
                            byte[] stateData = new byte[len];
                            Buffer.BlockCopy(data, i, stateData, 0, len);
                            i += len;
                            if (_recoverySessionData == null)
                            {
                                _currentSessionData._initialState[stateId] = stateData;
                            }
                            else
                            {
                                _currentSessionData._delta[stateId] = new SessionStateRecord { _data = stateData, _dataLength = len, _recoverable = true, _version = 0 };
                                _currentSessionData._deltaDirty = true;
                            }
                        }
                        break;
                    }

                case TdsEnums.FEATUREEXT_GLOBALTRANSACTIONS:
                    {
                        SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ADV> {0}, Received feature extension acknowledgement for GlobalTransactions", ObjectID);
                        if (data.Length < 1)
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Unknown version number for GlobalTransactions", ObjectID);
                            throw SQL.ParsingError();
                        }

                        IsGlobalTransaction = true;
                        if (1 == data[0])
                        {
                            IsGlobalTransactionsEnabledForServer = true;
                        }
                        break;
                    }
                case TdsEnums.FEATUREEXT_FEDAUTH:
                    {
                        SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ADV> {0}, Received feature extension acknowledgement for federated authentication", ObjectID);
                        if (!_federatedAuthenticationRequested)
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Did not request federated authentication", ObjectID);
                            throw SQL.ParsingErrorFeatureId(ParsingErrorState.UnrequestedFeatureAckReceived, featureId);
                        }

                        Debug.Assert(_fedAuthFeatureExtensionData != null, "_fedAuthFeatureExtensionData must not be null when _federatedAuthenticationRequested == true");

                        switch (_fedAuthFeatureExtensionData.libraryType)
                        {
                            case TdsEnums.FedAuthLibrary.MSAL:
                            case TdsEnums.FedAuthLibrary.SecurityToken:
                                // The server shouldn't have sent any additional data with the ack (like a nonce)
                                if (data.Length != 0)
                                {
                                    SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Federated authentication feature extension ack for MSAL and Security Token includes extra data", ObjectID);
                                    throw SQL.ParsingError(ParsingErrorState.FedAuthFeatureAckContainsExtraData);
                                }
                                break;

                            default:
                                Debug.Fail("Unknown _fedAuthLibrary type");
                                SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Attempting to use unknown federated authentication library", ObjectID);
                                throw SQL.ParsingErrorLibraryType(ParsingErrorState.FedAuthFeatureAckUnknownLibraryType, (int)_fedAuthFeatureExtensionData.libraryType);
                        }
                        _federatedAuthenticationAcknowledged = true;

                        // If a new authentication context was used as part of this login attempt, try to update the new context in the cache, i.e.dbConnectionPool.AuthenticationContexts.
                        // ChooseAuthenticationContextToUpdate will take care that only the context which has more validity will remain in the cache, based on the Update logic.
                        if (_newDbConnectionPoolAuthenticationContext != null)
                        {
                            Debug.Assert(_dbConnectionPool != null, "_dbConnectionPool should not be null when _newDbConnectionPoolAuthenticationContext != null.");

                            DbConnectionPoolAuthenticationContext newAuthenticationContextInCacheAfterAddOrUpdate = _dbConnectionPool.AuthenticationContexts.AddOrUpdate(_dbConnectionPoolAuthenticationContextKey, _newDbConnectionPoolAuthenticationContext,
                                                                                 (key, oldValue) => DbConnectionPoolAuthenticationContext.ChooseAuthenticationContextToUpdate(oldValue, _newDbConnectionPoolAuthenticationContext));

                            Debug.Assert(newAuthenticationContextInCacheAfterAddOrUpdate != null, "newAuthenticationContextInCacheAfterAddOrUpdate should not be null.");
#if DEBUG
                            // For debug purposes, assert and trace if we ended up updating the cache with the new one or some other thread's context won the expiration race.
                            if (newAuthenticationContextInCacheAfterAddOrUpdate == _newDbConnectionPoolAuthenticationContext)
                            {
                                SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Updated the new dbAuthenticationContext in the _dbConnectionPool.AuthenticationContexts.", ObjectID);
                            }
                            else
                            {
                                SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, AddOrUpdate attempted on _dbConnectionPool.AuthenticationContexts, but it did not update the new value.", ObjectID);
                            }
#endif
                        }

                        break;
                    }
                case TdsEnums.FEATUREEXT_TCE:
                    {
                        SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ADV> {0}, Received feature extension acknowledgement for TCE", ObjectID);
                        if (data.Length < 1)
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Unknown version number for TCE", ObjectID);
                            throw SQL.ParsingError(ParsingErrorState.TceUnknownVersion);
                        }

                        byte supportedTceVersion = data[0];
                        if (0 == supportedTceVersion || supportedTceVersion > TdsEnums.MAX_SUPPORTED_TCE_VERSION)
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Invalid version number for TCE", ObjectID);
                            throw SQL.ParsingErrorValue(ParsingErrorState.TceInvalidVersion, supportedTceVersion);
                        }

                        _tceVersionSupported = supportedTceVersion;
                        Debug.Assert(_tceVersionSupported <= TdsEnums.MAX_SUPPORTED_TCE_VERSION, "Client support TCE version 2");
                        _parser.IsColumnEncryptionSupported = true;
                        _parser.TceVersionSupported = _tceVersionSupported;
                        _parser.AreEnclaveRetriesSupported = _tceVersionSupported == 3;

                        if (data.Length > 1)
                        {
                            // Extract the type of enclave being used by the server.
                            _parser.EnclaveType = Encoding.Unicode.GetString(data, 2, (data.Length - 2));
                        }
                        break;
                    }

                case TdsEnums.FEATUREEXT_UTF8SUPPORT:
                    {
                        SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ADV> {0}, Received feature extension acknowledgement for UTF8 support", ObjectID);
                        if (data.Length < 1)
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Unknown value for UTF8 support", ObjectID);
                            throw SQL.ParsingError();
                        }
                        break;
                    }
                case TdsEnums.FEATUREEXT_DATACLASSIFICATION:
                    {
                        SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ADV> {0}, Received feature extension acknowledgement for DATACLASSIFICATION", ObjectID);
                        if (data.Length < 1)
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Unknown token for DATACLASSIFICATION", ObjectID);
                            throw SQL.ParsingError(ParsingErrorState.CorruptedTdsStream);
                        }
                        byte supportedDataClassificationVersion = data[0];
                        if ((0 == supportedDataClassificationVersion) || (supportedDataClassificationVersion > TdsEnums.DATA_CLASSIFICATION_VERSION_MAX_SUPPORTED))
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Invalid version number for DATACLASSIFICATION", ObjectID);
                            throw SQL.ParsingErrorValue(ParsingErrorState.DataClassificationInvalidVersion, supportedDataClassificationVersion);
                        }

                        if (data.Length != 2)
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Unknown token for DATACLASSIFICATION", ObjectID);
                            throw SQL.ParsingError(ParsingErrorState.CorruptedTdsStream);
                        }
                        byte enabled = data[1];
                        context.TdsStream.DataClassificationVersion = (enabled == 0) ? TdsEnums.DATA_CLASSIFICATION_NOT_ENABLED : supportedDataClassificationVersion;
                        break;
                    }

                case TdsEnums.FEATUREEXT_SQLDNSCACHING:
                    {
                        // SqlClientEventSource.Log.TryAdvancedTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ADV> {0}, Received feature extension acknowledgement for SQLDNSCACHING", ObjectID);

                        if (data.Length < 1)
                        {
                            // SqlClientEventSource.Log.TryTraceEvent("<sc.SqlInternalConnectionTds.OnFeatureExtAck|ERR> {0}, Unknown token for SQLDNSCACHING", ObjectID);
                            throw SQL.ParsingError(ParsingErrorState.CorruptedTdsStream);
                        }

                        if (1 == data[0])
                        {
                            IsSQLDNSCachingSupported = true;
                            _cleanSQLDNSCaching = false;

                            if (RoutingInfo != null)
                            {
                                IsDNSCachingBeforeRedirectSupported = true;
                            }
                        }
                        else
                        {
                            // we receive the IsSupported whose value is 0
                            IsSQLDNSCachingSupported = false;
                            _cleanSQLDNSCaching = true;
                        }

                        // need to add more steps for phase 2
                        // get IPv4 + IPv6 + Port number
                        // not put them in the DNS cache at this point but need to store them somewhere
                        // generate pendingSQLDNSObject and turn on IsSQLDNSRetryEnabled flag

                        break;
                    }

                default:
                    {
                        // Unknown feature ack
                        throw SQL.ParsingError();
                    }
            }
        }

        public static async ValueTask<SensitivityClassification> ProcessDataClassificationAsync(this TdsParserX parser, bool isAsync, CancellationToken ct)
        {
            if (parser.TdsContext.TdsStream.DataClassificationVersion == 0)
            {
                throw SQL.ParsingError(ParsingErrorState.DataClassificationNotExpected);
            }

            TdsReader tdsReader = parser.TdsContext.TdsStream.TdsReader;

            // get the labels
            ushort numLabels = await tdsReader.ReadUInt16Async(isAsync, ct).ConfigureAwait(false);
            List<Label> labels = new List<Label>(numLabels);

            for (ushort i = 0; i < numLabels; i++)
            {
                string label = await tdsReader.ReadByteStringAsync(isAsync, ct).ConfigureAwait(false);
                string id = await tdsReader.ReadByteStringAsync(isAsync, ct).ConfigureAwait(false);
                labels.Add(new Label(label, id));
            }

            // get the information types
            ushort numInformationTypes = await tdsReader.ReadUInt16Async(isAsync, ct).ConfigureAwait(false);
            List<InformationType> informationTypes = new List<InformationType>(numInformationTypes);

            for (ushort i = 0; i < numInformationTypes; i++)
            {
                string informationType = await tdsReader.ReadByteStringAsync(isAsync, ct).ConfigureAwait(false);
                string id = await tdsReader.ReadByteStringAsync(isAsync, ct).ConfigureAwait(false);
                informationTypes.Add(new InformationType(informationType, id));
            }

            // get sensitivity rank
            int sensitivityRank = (int)SensitivityRank.NOT_DEFINED;
            if (parser.TdsContext.TdsStream.DataClassificationVersion > TdsEnums.DATA_CLASSIFICATION_VERSION_WITHOUT_RANK_SUPPORT)
            {
                sensitivityRank = await tdsReader.ReadInt32Async(isAsync, ct).ConfigureAwait(false);
                if (!Enum.IsDefined(typeof(SensitivityRank), sensitivityRank))
                {
                    return null;
                }
            }

            // get the per column classification data (corresponds to order of output columns for query)
            ushort numResultColumns = await tdsReader.ReadUInt16Async(isAsync, ct).ConfigureAwait(false);
            List<ColumnSensitivity> columnSensitivities = new List<ColumnSensitivity>(numResultColumns);
            for (ushort columnNum = 0; columnNum < numResultColumns; columnNum++)
            {
                // get sensitivity properties for all the different sources which were used in generating the column output
                ushort numSources = await tdsReader.ReadUInt16Async(isAsync, ct).ConfigureAwait(false);
                List<SensitivityProperty> sensitivityProperties = new List<SensitivityProperty>(numSources);
                for (ushort sourceNum = 0; sourceNum < numSources; sourceNum++)
                {
                    // get the label index and then lookup label to use for source
                    ushort labelIndex = await tdsReader.ReadUInt16Async(isAsync, ct).ConfigureAwait(false);
                    Label label = null;
                    if (labelIndex != ushort.MaxValue)
                    {
                        if (labelIndex >= labels.Count)
                        {
                            throw SQL.ParsingError(ParsingErrorState.DataClassificationInvalidLabelIndex);
                        }
                        label = labels[labelIndex];
                    }

                    // get the information type index and then lookup information type to use for source
                    ushort informationTypeIndex = await tdsReader.ReadUInt16Async(isAsync, ct).ConfigureAwait(false);
                    InformationType informationType = null;
                    if (informationTypeIndex != ushort.MaxValue)
                    {
                        if (informationTypeIndex >= informationTypes.Count)
                        {
                            throw SQL.ParsingError(ParsingErrorState.DataClassificationInvalidInformationTypeIndex);
                        }
                        informationType = informationTypes[informationTypeIndex];
                    }

                    // get sensitivity rank
                    int sensitivityRankProperty = (int)SensitivityRank.NOT_DEFINED;
                    if (parser.TdsContext.TdsStream.DataClassificationVersion > TdsEnums.DATA_CLASSIFICATION_VERSION_WITHOUT_RANK_SUPPORT)
                    {
                        sensitivityRankProperty = await tdsReader.ReadInt32Async(isAsync, ct).ConfigureAwait(false);
                        if (!Enum.IsDefined(typeof(SensitivityRank), sensitivityRankProperty))
                        {
                            return null;
                        }
                    }

                    // add sensitivity properties for the source
                    sensitivityProperties.Add(new SensitivityProperty(label, informationType, (SensitivityRank)sensitivityRankProperty));
                }
                columnSensitivities.Add(new ColumnSensitivity(sensitivityProperties));
            }

            return new SensitivityClassification(labels, informationTypes, columnSensitivities, (SensitivityRank)sensitivityRank);
        }
    }
}
#endif

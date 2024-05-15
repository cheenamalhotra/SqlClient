// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Data.SqlClientX.TDS.Handlers;
using Microsoft.Data.SqlClientX.TDS.Types;

namespace Microsoft.Data.SqlClientX.TDS
{
    internal class TDSExecutor
    {
        private readonly IBufferHandler _bufferHandler;
        private readonly IBufferTypesHandler _typesHandler;
        private readonly INetworkHandler _networkHandler;
        private readonly IStateHandler _stateHandler;
        private readonly ITimeoutHandler _timeoutHandler;
        private readonly IDataSerializer _dataParser;

        public TDSExecutor(IBufferHandler bufferHandler,
            IBufferTypesHandler typesHandler,
            INetworkHandler networkHandler,
            IStateHandler stateHandler,
            ITimeoutHandler timeoutHandler,
            IDataSerializer dataParser) {
            _bufferHandler = bufferHandler;
            _typesHandler = typesHandler;
            _networkHandler = networkHandler;
            _stateHandler = stateHandler;
            _timeoutHandler = timeoutHandler;
            _dataParser = dataParser;
        }

        #region Public APIs

        // Main parse loop for the top-level tds tokens, calls back into the I*Handler interfaces
        public async Task<bool> RunAsync(RunBehavior runBehavior, SqlCommand cmdHandler, SqlDataReader dataStream, BulkCopySimpleResultSet bulkCopyHandler, TdsParserStateObject stateObj, out bool dataReady)
        {
            Debug.Assert((SniContext.Undefined != stateObj.SniContext) &&       // SniContext must not be Undefined
                ((stateObj._attentionSent) || ((SniContext.Snix_Execute != stateObj.SniContext) && (SniContext.Snix_SendRows != stateObj.SniContext))),  // SniContext should not be Execute or SendRows unless attention was sent (and, therefore, we are looking for an ACK)
                         $"Unexpected SniContext on call to TryRun; SniContext={stateObj.SniContext}");

            if (TdsParserState.Broken == _stateHandler.GetCurrentState() || TdsParserState.Closed == _stateHandler.GetCurrentState())
            {
                dataReady = true;
                return true; // Just in case this is called in a loop, expecting data to be returned.
            }

            dataReady = false;

            do
            {
                // If there is data ready, but we didn't exit the loop, then something is wrong
                Debug.Assert(!dataReady, "dataReady not expected - did we forget to skip the row?");

                if (stateObj.IsTimeoutStateExpired)
                {
                    runBehavior = RunBehavior.Attention;
                }

                if (TdsParserState.Broken == _stateHandler.GetCurrentState() || TdsParserState.Closed == _stateHandler.GetCurrentState())
                    break; // jump out of the loop if the state is already broken or closed.

                if (!stateObj._accumulateInfoEvents && (stateObj._pendingInfoEvents != null))
                {
                    if (RunBehavior.Clean != (RunBehavior.Clean & runBehavior))
                    {
                        SqlConnection connection = null;
                        if (_connHandler != null)
                            connection = _connHandler.Connection; // SqlInternalConnection holds the user connection object as a weak ref
                        // We are omitting checks for error.Class in the code below (see processing of INFO) since we know (and assert) that error class
                        // error.Class < TdsEnums.MIN_ERROR_CLASS for info message.
                        // Also we know that TdsEnums.MIN_ERROR_CLASS<TdsEnums.MAX_USER_CORRECTABLE_ERROR_CLASS
                        if ((connection != null) && connection.FireInfoMessageEventOnUserErrors)
                        {
                            foreach (SqlError error in stateObj._pendingInfoEvents)
                            {
                                FireInfoMessageEvent(connection, cmdHandler, stateObj, error);
                            }
                        }
                        else
                            foreach (SqlError error in stateObj._pendingInfoEvents)
                            {
                                stateObj.AddWarning(error);
                            }
                    }
                    stateObj._pendingInfoEvents = null;
                }

                byte token;
                if (!stateObj.TryReadByte(out token))
                {
                    return false;
                }

                if (!IsValidTdsToken(token))
                {
                    Debug.Fail($"unexpected token; token = {token,-2:X2}");
                    _stateHandler.UpdateState(TdsParserState.Broken);
                    _connHandler.BreakConnection();
                    SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.Run|ERR> Potential multi-threaded misuse of connection, unexpected TDS token found {0}", ObjectID);
                    throw SQL.ParsingError();
                }

                int tokenLength;
                if (!TryGetTokenLength(token, stateObj, out tokenLength))
                {
                    return false;
                }

                switch (token)
                {
                    case TdsEnums.SQLERROR:
                    case TdsEnums.SQLINFO:
                        {
                            if (token == TdsEnums.SQLERROR)
                            {
                                stateObj.HasReceivedError = true; // Keep track of the fact error token was received - for Done processing.
                            }

                            SqlError error;
                            if (!TryProcessError(token, stateObj, cmdHandler, out error))
                            {
                                return false;
                            }

                            if (token == TdsEnums.SQLINFO && stateObj._accumulateInfoEvents)
                            {
                                Debug.Assert(error.Class < TdsEnums.MIN_ERROR_CLASS, "INFO with class > TdsEnums.MIN_ERROR_CLASS");

                                if (stateObj._pendingInfoEvents == null)
                                    stateObj._pendingInfoEvents = new List<SqlError>();
                                stateObj._pendingInfoEvents.Add(error);
                                stateObj._syncOverAsync = true;
                                break;
                            }

                            if (RunBehavior.Clean != (RunBehavior.Clean & runBehavior))
                            {
                                // If FireInfoMessageEventOnUserErrors is true, we have to fire event without waiting.
                                // Otherwise we can go ahead and add it to errors/warnings collection.
                                SqlConnection connection = null;
                                if (_connHandler != null)
                                    connection = _connHandler.Connection; // SqlInternalConnection holds the user connection object as a weak ref

                                if ((connection != null) &&
                                    (connection.FireInfoMessageEventOnUserErrors == true) &&
                                    (error.Class <= TdsEnums.MAX_USER_CORRECTABLE_ERROR_CLASS))
                                {
                                    // Fire SqlInfoMessage here
                                    FireInfoMessageEvent(connection, cmdHandler, stateObj, error);
                                }
                                else
                                {
                                    // insert error/info into the appropriate exception - warning if info, exception if error
                                    if (error.Class < TdsEnums.MIN_ERROR_CLASS)
                                    {
                                        stateObj.AddWarning(error);
                                    }
                                    else if (error.Class < TdsEnums.FATAL_ERROR_CLASS)
                                    {
                                        // Continue results processing for all non-fatal errors (<20)

                                        stateObj.AddError(error);

                                        // Add it to collection - but do NOT change run behavior UNLESS
                                        // we are in an ExecuteReader call - at which time we will be throwing
                                        // anyways so we need to consume all errors.  This is not the case
                                        // if we have already given out a reader.  If we have already given out
                                        // a reader we need to throw the error but not halt further processing.  We used to
                                        // halt processing.

                                        if (null != dataStream)
                                        {
                                            if (!dataStream.IsInitialized)
                                            {
                                                runBehavior = RunBehavior.UntilDone;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        stateObj.AddError(error);

                                        // Else we have a fatal error and we need to change the behavior
                                        // since we want the complete error information in the exception.
                                        // Besides - no further results will be received.
                                        runBehavior = RunBehavior.UntilDone;
                                    }
                                }
                            }
                            else if (error.Class >= TdsEnums.FATAL_ERROR_CLASS)
                            {
                                stateObj.AddError(error);
                            }
                            break;
                        }

                    case TdsEnums.SQLCOLINFO:
                        {
                            if (null != dataStream)
                            {
                                _SqlMetaDataSet metaDataSet;
                                if (!TryProcessColInfo(dataStream.MetaData, dataStream, stateObj, out metaDataSet))
                                {
                                    return false;
                                }
                                if (!dataStream.TrySetMetaData(metaDataSet, false))
                                {
                                    return false;
                                }
                                dataStream.BrowseModeInfoConsumed = true;
                            }
                            else
                            { // no dataStream
                                if (!stateObj.TrySkipBytes(tokenLength))
                                {
                                    return false;
                                }
                            }
                            break;
                        }

                    case TdsEnums.SQLDONE:
                    case TdsEnums.SQLDONEPROC:
                    case TdsEnums.SQLDONEINPROC:
                        {
                            // RunBehavior can be modified
                            if (!TryProcessDone(cmdHandler, dataStream, ref runBehavior, stateObj))
                            {
                                return false;
                            }
                            if ((token == TdsEnums.SQLDONEPROC) && (cmdHandler != null))
                            {
                                // If the current parse/read is for the results of describe parameter encryption RPC requests,
                                // call a different handler which will update the describe parameter encryption RPC structures
                                // with the results, instead of the actual user RPC requests.
                                if (cmdHandler.IsDescribeParameterEncryptionRPCCurrentlyInProgress)
                                {
                                    cmdHandler.OnDoneDescribeParameterEncryptionProc(stateObj);
                                }
                                else
                                {
                                    cmdHandler.OnDoneProc(stateObj);
                                }
                            }

                            break;
                        }

                    case TdsEnums.SQLORDER:
                        {
                            // don't do anything with the order token so read off the pipe
                            if (!stateObj.TrySkipBytes(tokenLength))
                            {
                                return false;
                            }
                            break;
                        }

                    case TdsEnums.SQLENVCHANGE:
                        {
                            // ENVCHANGE must be processed synchronously (since it can modify the state of many objects)
                            stateObj._syncOverAsync = true;

                            SqlEnvChange env;
                            if (!TryProcessEnvChange(tokenLength, stateObj, out env))
                            {
                                return false;
                            }

                            while (env != null)
                            {
                                if (!this.Connection.IgnoreEnvChange)
                                {
                                    switch (env._type)
                                    {
                                        case TdsEnums.ENV_BEGINTRAN:
                                        case TdsEnums.ENV_ENLISTDTC:
                                            // When we get notification from the server of a new
                                            // transaction, we move any pending transaction over to
                                            // the current transaction, then we store the token in it.
                                            // if there isn't a pending transaction, then it's either
                                            // a TSQL transaction or a distributed transaction.
                                            Debug.Assert(null == _currentTransaction, "non-null current transaction with an ENV Change");
                                            _currentTransaction = _pendingTransaction;
                                            _pendingTransaction = null;

                                            if (null != _currentTransaction)
                                            {
                                                _currentTransaction.TransactionId = env._newLongValue;   // this is defined as a ULongLong in the server and in the TDS Spec.
                                            }
                                            else
                                            {
                                                TransactionType transactionType = (TdsEnums.ENV_BEGINTRAN == env._type) ? TransactionType.LocalFromTSQL : TransactionType.Distributed;
                                                _currentTransaction = new SqlInternalTransaction(_connHandler, transactionType, null, env._newLongValue);
                                            }
                                            if (null != _statistics && !_statisticsIsInTransaction)
                                            {
                                                _statistics.SafeIncrement(ref _statistics._transactions);
                                            }
                                            _statisticsIsInTransaction = true;
                                            _retainedTransactionId = SqlInternalTransaction.NullTransactionId;
                                            break;
                                        case TdsEnums.ENV_DEFECTDTC:
                                        case TdsEnums.ENV_TRANSACTIONENDED:
                                        case TdsEnums.ENV_COMMITTRAN:
                                            //  Must clear the retain id if the server-side transaction ends by anything other
                                            //  than rollback.
                                            _retainedTransactionId = SqlInternalTransaction.NullTransactionId;
                                            goto case TdsEnums.ENV_ROLLBACKTRAN;
                                        case TdsEnums.ENV_ROLLBACKTRAN:
                                            // When we get notification of a completed transaction
                                            // we null out the current transaction.
                                            if (null != _currentTransaction)
                                            {
#if DEBUG
                                                // Check null for case where Begin and Rollback obtained in the same message.
                                                if (SqlInternalTransaction.NullTransactionId != _currentTransaction.TransactionId)
                                                {
                                                    Debug.Assert(_currentTransaction.TransactionId != env._newLongValue, "transaction id's are not equal!");
                                                }
#endif

                                                if (TdsEnums.ENV_COMMITTRAN == env._type)
                                                {
                                                    _currentTransaction.Completed(TransactionState.Committed);
                                                }
                                                else if (TdsEnums.ENV_ROLLBACKTRAN == env._type)
                                                {
                                                    //  Hold onto transaction id if distributed tran is rolled back.  This must
                                                    //  be sent to the server on subsequent executions even though the transaction
                                                    //  is considered to be rolled back.
                                                    if (_currentTransaction.IsDistributed && _currentTransaction.IsActive)
                                                    {
                                                        _retainedTransactionId = env._oldLongValue;
                                                    }
                                                    _currentTransaction.Completed(TransactionState.Aborted);
                                                }
                                                else
                                                {
                                                    _currentTransaction.Completed(TransactionState.Unknown);
                                                }
                                                _currentTransaction = null;
                                            }
                                            _statisticsIsInTransaction = false;
                                            break;

                                        default:
                                            _connHandler.OnEnvChange(env);
                                            break;
                                    }
                                }
                                SqlEnvChange head = env;
                                env = env._next;
                                head.Clear();
                                head = null;
                            }
                            break;
                        }
                    case TdsEnums.SQLLOGINACK:
                        {
                            SqlClientEventSource.Log.TryTraceEvent("<sc.TdsParser.TryRun|SEC> Received login acknowledgement token");
                            SqlLoginAck ack;
                            if (!TryProcessLoginAck(stateObj, out ack))
                            {
                                return false;
                            }

                            _connHandler.OnLoginAck(ack);
                            break;
                        }
                    case TdsEnums.SQLFEATUREEXTACK:
                        {
                            if (!TryProcessFeatureExtAck(stateObj))
                            {
                                return false;
                            }
                            break;
                        }
                    case TdsEnums.SQLFEDAUTHINFO:
                        {
                            _connHandler._federatedAuthenticationInfoReceived = true;
                            SqlFedAuthInfo info;

                            if (!TryProcessFedAuthInfo(stateObj, tokenLength, out info))
                            {
                                return false;
                            }
                            _connHandler.OnFedAuthInfo(info);
                            break;
                        }
                    case TdsEnums.SQLSESSIONSTATE:
                        {
                            if (!TryProcessSessionState(stateObj, tokenLength, _connHandler._currentSessionData))
                            {
                                return false;
                            }
                            break;
                        }
                    case TdsEnums.SQLCOLMETADATA:
                        {
                            if (tokenLength != TdsEnums.VARNULL)
                            {
                                _SqlMetaDataSet metadata;
                                if (!TryProcessMetaData(tokenLength, stateObj, out metadata, cmdHandler?.ColumnEncryptionSetting ?? SqlCommandColumnEncryptionSetting.UseConnectionSetting))
                                {
                                    return false;
                                }
                                stateObj._cleanupMetaData = metadata;
                            }
                            else
                            {
                                if (cmdHandler != null)
                                {
                                    stateObj._cleanupMetaData = cmdHandler.MetaData;
                                }
                            }

                            byte peekedToken;
                            if (!stateObj.TryPeekByte(out peekedToken))
                            { // temporarily cache next byte
                                return false;
                            }

                            if (TdsEnums.SQLDATACLASSIFICATION == peekedToken)
                            {
                                byte dataClassificationToken;
                                if (!stateObj.TryReadByte(out dataClassificationToken))
                                {
                                    return false;
                                }
                                Debug.Assert(TdsEnums.SQLDATACLASSIFICATION == dataClassificationToken);

                                SensitivityClassification sensitivityClassification;
                                if (!TryProcessDataClassification(stateObj, out sensitivityClassification))
                                {
                                    return false;
                                }
                                if (null != dataStream && !dataStream.TrySetSensitivityClassification(sensitivityClassification))
                                {
                                    return false;
                                }

                                // update peekedToken
                                if (!stateObj.TryPeekByte(out peekedToken))
                                {
                                    return false;
                                }
                            }

                            if (null != dataStream)
                            {
                                if (!dataStream.TrySetMetaData(stateObj._cleanupMetaData, (TdsEnums.SQLTABNAME == peekedToken || TdsEnums.SQLCOLINFO == peekedToken)))
                                {
                                    return false;
                                }
                            }
                            else if (null != bulkCopyHandler)
                            {
                                bulkCopyHandler.SetMetaData(stateObj._cleanupMetaData);
                            }
                            break;
                        }
                    case TdsEnums.SQLROW:
                    case TdsEnums.SQLNBCROW:
                        {
                            Debug.Assert(stateObj._cleanupMetaData != null, "Reading a row, but the metadata is null");

                            if (token == TdsEnums.SQLNBCROW)
                            {
                                if (!stateObj.TryStartNewRow(isNullCompressed: true, nullBitmapColumnsCount: stateObj._cleanupMetaData.Length))
                                {
                                    return false;
                                }
                            }
                            else
                            {
                                if (!stateObj.TryStartNewRow(isNullCompressed: false))
                                {
                                    return false;
                                }
                            }

                            if (null != bulkCopyHandler)
                            {
                                if (!TryProcessRow(stateObj._cleanupMetaData, bulkCopyHandler.CreateRowBuffer(), bulkCopyHandler.CreateIndexMap(), stateObj))
                                {
                                    return false;
                                }
                            }
                            else if (RunBehavior.ReturnImmediately != (RunBehavior.ReturnImmediately & runBehavior))
                            {
                                if (!TrySkipRow(stateObj._cleanupMetaData, stateObj))
                                { // skip rows
                                    return false;
                                }
                            }
                            else
                            {
                                dataReady = true;
                            }

                            if (_statistics != null)
                            {
                                _statistics.WaitForDoneAfterRow = true;
                            }
                            break;
                        }
                    case TdsEnums.SQLRETURNSTATUS:
                        int status;
                        if (!stateObj.TryReadInt32(out status))
                        {
                            return false;
                        }
                        if (cmdHandler != null)
                        {
                            cmdHandler.OnReturnStatus(status);
                        }
                        break;
                    case TdsEnums.SQLRETURNVALUE:
                        {
                            SqlReturnValue returnValue;
                            if (!TryProcessReturnValue(tokenLength, stateObj, out returnValue, cmdHandler?.ColumnEncryptionSetting ?? SqlCommandColumnEncryptionSetting.UseConnectionSetting))
                            {
                                return false;
                            }
                            if (cmdHandler != null)
                            {
                                cmdHandler.OnReturnValue(returnValue, stateObj);
                            }
                            break;
                        }
                    case TdsEnums.SQLSSPI:
                        {
                            // token length is length of SSPI data - call ProcessSSPI with it

                            Debug.Assert(stateObj._syncOverAsync, "ProcessSSPI does not support retry, do not attempt asynchronously");
                            stateObj._syncOverAsync = true;

                            ProcessSSPI(tokenLength);
                            break;
                        }
                    case TdsEnums.SQLTABNAME:
                        {
                            if (null != dataStream)
                            {
                                MultiPartTableName[] tableNames;
                                if (!TryProcessTableName(tokenLength, stateObj, out tableNames))
                                {
                                    return false;
                                }
                                dataStream.TableNames = tableNames;
                            }
                            else
                            {
                                if (!stateObj.TrySkipBytes(tokenLength))
                                {
                                    return false;
                                }
                            }
                            break;
                        }
                    case TdsEnums.SQLRESCOLSRCS:
                        {
                            if (!TryProcessResColSrcs(stateObj, tokenLength))
                            {
                                return false;
                            }
                            break;
                        }

                    // deprecated
                    case TdsEnums.SQLALTMETADATA:
                        {
                            stateObj.CloneCleanupAltMetaDataSetArray();

                            if (stateObj._cleanupAltMetaDataSetArray == null)
                            {
                                // create object on demand (lazy creation)
                                stateObj._cleanupAltMetaDataSetArray = new _SqlMetaDataSetCollection();
                            }

                            _SqlMetaDataSet cleanupAltMetaDataSet;
                            if (!TryProcessAltMetaData(tokenLength, stateObj, out cleanupAltMetaDataSet))
                            {
                                return false;
                            }

                            stateObj._cleanupAltMetaDataSetArray.SetAltMetaData(cleanupAltMetaDataSet);
                            if (null != dataStream)
                            {
                                byte metadataConsumedByte;
                                if (!stateObj.TryPeekByte(out metadataConsumedByte))
                                {
                                    return false;
                                }
                                if (!dataStream.TrySetAltMetaDataSet(cleanupAltMetaDataSet, (TdsEnums.SQLALTMETADATA != metadataConsumedByte)))
                                {
                                    return false;
                                }
                            }

                            break;
                        }
                    case TdsEnums.SQLALTROW:
                        {
                            if (!stateObj.TryStartNewRow(isNullCompressed: false))
                            { // altrows are not currently null compressed
                                return false;
                            }

                            // read will call run until dataReady. Must not read any data if ReturnImmediately set
                            if (RunBehavior.ReturnImmediately != (RunBehavior.ReturnImmediately & runBehavior))
                            {
                                ushort altRowId;
                                if (!stateObj.TryReadUInt16(out altRowId))
                                { // get altRowId
                                    return false;
                                }

                                if (!TrySkipRow(stateObj._cleanupAltMetaDataSetArray.GetAltMetaData(altRowId), stateObj))
                                { // skip altRow
                                    return false;
                                }
                            }
                            else
                            {
                                dataReady = true;
                            }

                            break;
                        }

                    default:
                        Debug.Fail("Unhandled token:  " + token.ToString(CultureInfo.InvariantCulture));
                        break;
                }

                Debug.Assert(stateObj.HasPendingData || !dataReady, "dataReady is set, but there is no pending data");
            }

            // Loop while data pending & runbehavior not return immediately, OR
            // if in attention case, loop while no more pending data & attention has not yet been
            // received.
            while ((stateObj.HasPendingData &&
                    (RunBehavior.ReturnImmediately != (RunBehavior.ReturnImmediately & runBehavior))) ||
                (!stateObj.HasPendingData && stateObj._attentionSent && !stateObj.HasReceivedAttention));

#if DEBUG
            if ((stateObj.HasPendingData) && (!dataReady))
            {
                byte token;
                if (!stateObj.TryPeekByte(out token))
                {
                    return false;
                }
                Debug.Assert(IsValidTdsToken(token), $"DataReady is false, but next token is not valid: {token,-2:X2}");
            }
#endif

            if (!stateObj.HasPendingData)
            {
                if (null != CurrentTransaction)
                {
                    CurrentTransaction.Activate();
                }
            }

            // if we received an attention (but this thread didn't send it) then
            // we throw an Operation Cancelled error
            if (stateObj.HasReceivedAttention)
            {
                // Dev11 #344723: SqlClient stress test suspends System_Data!Tcp::ReadSync via a call to SqlDataReader::Close
                // Spin until SendAttention has cleared _attentionSending, this prevents a race condition between receiving the attention ACK and setting _attentionSent
                TryRunSetupSpinWaitContinuation(stateObj);

                Debug.Assert(stateObj._attentionSent, "Attention ACK has been received without attention sent");
                if (stateObj._attentionSent)
                {
                    // Reset attention state.
                    stateObj._attentionSent = false;
                    stateObj.HasReceivedAttention = false;

                    if (RunBehavior.Clean != (RunBehavior.Clean & runBehavior) && !stateObj.IsTimeoutStateExpired)
                    {
                        // Add attention error to collection - if not RunBehavior.Clean!
                        stateObj.AddError(new SqlError(0, 0, TdsEnums.MIN_ERROR_CLASS, _server, SQLMessage.OperationCancelled(), "", 0, exception: null, batchIndex: cmdHandler?.GetCurrentBatchIndex() ?? -1));
                    }
                }
            }

            if (stateObj.HasErrorOrWarning)
            {
                ThrowExceptionAndWarning(stateObj, cmdHandler);
            }
            return true;
        }

        // Read data from network
        public Task StartReadAsync()
        {

        }
        #endregion

        #region Private helpers



        #endregion
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET8_0_OR_GREATER

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Common;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClientX.Tds.State;
using Microsoft.Data.SqlClientX.Tds.Tokens;
using Microsoft.Data.SqlClientX.Tds.Tokens.EnvChange;
using Microsoft.Data.SqlClientX.Tds.Tokens.Error;
using static Microsoft.Data.SqlClientX.Tds.State.TdsTimeoutState;

namespace Microsoft.Data.SqlClientX.Tds
{
    internal class TdsParserX
    {
        private readonly TdsContext _tdsContext;

        private readonly TokenStreamHandler _tokenStreamHandler;

        public TdsParserX(TdsContext context)
        {
            _tdsContext = context;
            _tokenStreamHandler = new TokenStreamHandler();
        }

        internal async ValueTask<bool> RunAsync(RunBehavior runBehavior, SqlCommand cmdHandler, SqlDataReader dataStream, BulkCopySimpleResultSet bulkCopyHandler, bool isAsync, CancellationToken ct)
        {
            //Debug.Assert((SniContext.Undefined != parserState.SniparserState) &&       // SniparserState must not be Undefined
            //    ((parserState._attentionSent) || ((SniContext.Snix_Execute != parserState.SniparserState) && (SniContext.Snix_SendRows != parserState.SniparserState))),  // SniparserState should not be Execute or SendRows unless attention was sent (and, therefore, we are looking for an ACK)
            //             $"Unexpected SniparserState on call to TryRun; SniparserState={parserState.SniparserState}");

            if (TdsParserState.Broken == _tdsContext.ParserState || TdsParserState.Closed == _tdsContext.ParserState)
            {
                return true; // Just in case this is called in a loop, expecting data to be returned.
            }

            bool dataReady = false;

            do
            {
                // If there is data ready, but we didn't exit the loop, then something is wrong
                Debug.Assert(!dataReady, "dataReady not expected - did we forget to skip the row?");

                if (_tdsContext.TimeoutState.IsTimeoutStateExpired)
                {
                    runBehavior = RunBehavior.Attention;
                }

                if (TdsParserState.Broken == _tdsContext.ParserState || TdsParserState.Closed == _tdsContext.ParserState)
                    break; // jump out of the loop if the state is already broken or closed.

                if (!_tdsContext._accumulateInfoEvents && (_tdsContext._pendingInfoEvents != null))
                {
                    if (RunBehavior.Clean != (RunBehavior.Clean & runBehavior))
                    {
                        SqlConnectionX connection = null;
                        if (_tdsContext.SqlConnector != null)
                            connection = _tdsContext.SqlConnector.OwningConnection; // SqlInternalConnection holds the user connection object as a weak ref
                        // We are omitting checks for error.Class in the code below (see processing of INFO) since we know (and assert) that error class
                        // error.Class < TdsEnums.MIN_ERROR_CLASS for info message.
                        // Also we know that TdsEnums.MIN_ERROR_CLASS<TdsEnums.MAX_USER_CORRECTABLE_ERROR_CLASS
                        if ((connection != null) && connection.FireInfoMessageEventOnUserErrors)
                        {
                            foreach (SqlError error in _tdsContext._pendingInfoEvents)
                            {
                                TdsUtils.FireInfoMessageEvent(_tdsContext, connection, null, error);
                            }
                        }
                        else
                            foreach (SqlError error in _tdsContext._pendingInfoEvents)
                            {
                                _tdsContext.TdsErrorWarningsState.AddWarning(error);
                            }
                    }
                    _tdsContext._pendingInfoEvents = null;
                }
                Token token = await _tokenStreamHandler.ReceiveTokenAsync(_tdsContext, isAsync, ct).ConfigureAwait(false);

                ProcessToken(runBehavior, token, _tdsContext.ParserState, cmdHandler, dataStream);

                Debug.Assert(_tdsContext.TdsSnapshotState.HasPendingData || !dataReady, "dataReady is set, but there is no pending data");
            }

            // Loop while data pending & runbehavior not return immediately, OR
            // if in attention case, loop while no more pending data & attention has not yet been
            // received.
            while ((_tdsContext.TdsSnapshotState.HasPendingData &&
                    (RunBehavior.ReturnImmediately != (RunBehavior.ReturnImmediately & runBehavior))) ||
                (!_tdsContext.TdsSnapshotState.HasPendingData && _tdsContext.TimeoutState._attentionSent && !_tdsContext.TdsSnapshotState.HasReceivedAttention));

            //#if DEBUG
            //            if ((parserState.HasPendingData) && (!dataReady))
            //            {
            //                byte token;
            //                if (!parserState.TryPeekByte(out token))
            //                {
            //                    return false;
            //                }
            //                Debug.Assert(IsValidTdsToken(token), $"DataReady is false, but next token is not valid: {token,-2:X2}");
            //            }
            //#endif

            if (!_tdsContext.TdsSnapshotState.HasPendingData)
            {
                if (null != _tdsContext.TdsTransactionState.CurrentTransaction)
                {
                    _tdsContext.TdsTransactionState.CurrentTransaction.Activate();
                }
            }

            // if we received an attention (but this thread didn't send it) then
            // we throw an Operation Cancelled error
            if (_tdsContext.TdsSnapshotState.HasReceivedAttention)
            {
                // Dev11 #344723: SqlClient stress test suspends System_Data!Tcp::ReadSync via a call to SqlDataReader::Close
                // Spin until SendAttention has cleared _attentionSending, this prevents a race condition between receiving the attention ACK and setting _attentionSent
                SpinWait.SpinUntil(() => !_tdsContext.TimeoutState._attentionSending);


                Debug.Assert(_tdsContext.TimeoutState._attentionSent, "Attention ACK has been received without attention sent");
                if (_tdsContext.TimeoutState._attentionSent)
                {
                    // Reset attention state.
                    _tdsContext.TimeoutState._attentionSent = false;
                    _tdsContext.TdsSnapshotState.HasReceivedAttention = false;

                    if (RunBehavior.Clean != (RunBehavior.Clean & runBehavior) && !_tdsContext.TimeoutState.IsTimeoutStateExpired)
                    {
                        // Add attention error to collection - if not RunBehavior.Clean!
                        _tdsContext.TdsErrorWarningsState.AddError(new SqlError(0, 0, TdsEnums.MIN_ERROR_CLASS, _tdsContext.ConnectionState.Server, SQLMessage.OperationCancelled(), "", 0, exception: null, batchIndex: -1));
                    }
                }
            }

            if (_tdsContext.TdsErrorWarningsState.HasErrorOrWarning)
            {
                TdsUtils.ThrowExceptionAndWarning(_tdsContext, cmdHandler);
            }
            return true;
        }

        private void ProcessToken(RunBehavior runBehavior, Token token, TdsParserState parserState, SqlCommand cmdHandler, SqlDataReader dataReader)
        {
            switch (token.Type)
            {
                case TokenType.Error:
                case TokenType.Info:
                    {
                        if (token.Type == TokenType.Error)
                        {
                            _tdsContext.TdsSnapshotState.HasReceivedError = true; // Keep track of the fact error token was received - for Done processing.
                        }

                        ErrorToken errorToken = (ErrorToken)token;
                        SqlError error = new SqlError(errorToken.Number, errorToken.State, errorToken.Severity, _tdsContext.ConnectionState.Server, errorToken.Message, errorToken.ProcName, errorToken.LineNumber, exception: null, -1);

                        if (token.Type == TokenType.Info && _tdsContext._accumulateInfoEvents)
                        {
                            Debug.Assert(error.Class < TdsEnums.MIN_ERROR_CLASS, "INFO with class > TdsEnums.MIN_ERROR_CLASS");

                            if (_tdsContext._pendingInfoEvents == null)
                                _tdsContext._pendingInfoEvents = new List<SqlError>();
                            _tdsContext._pendingInfoEvents.Add(error);
                            break;
                        }

                        if (RunBehavior.Clean != (RunBehavior.Clean & runBehavior))
                        {
                            // If FireInfoMessageEventOnUserErrors is true, we have to fire event without waiting.
                            // Otherwise we can go ahead and add it to errors/warnings collection.
                            SqlConnectionX connection = null;
                            if (_tdsContext.SqlConnector != null)
                                connection = _tdsContext.SqlConnector.OwningConnection; // SqlInternalConnection holds the user connection object as a weak ref

                            if ((connection != null) &&
                                (connection.FireInfoMessageEventOnUserErrors == true) &&
                                (error.Class <= TdsEnums.MAX_USER_CORRECTABLE_ERROR_CLASS))
                            {
                                // Fire SqlInfoMessage here
                                TdsUtils.FireInfoMessageEvent(_tdsContext, connection, null, error);
                            }
                            else
                            {
                                // insert error/info into the appropriate exception - warning if info, exception if error
                                if (error.Class < TdsEnums.MIN_ERROR_CLASS)
                                {
                                    _tdsContext.TdsErrorWarningsState.AddWarning(error);
                                }
                                else if (error.Class < TdsEnums.FATAL_ERROR_CLASS)
                                {
                                    // Continue results processing for all non-fatal errors (<20)

                                    _tdsContext.TdsErrorWarningsState.AddError(error);

                                    // Add it to collection - but do NOT change run behavior UNLESS
                                    // we are in an ExecuteReader call - at which time we will be throwing
                                    // anyways so we need to consume all errors.  This is not the case
                                    // if we have already given out a reader.  If we have already given out
                                    // a reader we need to throw the error but not halt further processing.  We used to
                                    // halt processing.

                                    if (null != dataReader)
                                    {
                                        if (!dataReader.IsInitialized)
                                        {
                                            runBehavior = RunBehavior.UntilDone;
                                        }
                                    }
                                }
                                else
                                {
                                    _tdsContext.TdsErrorWarningsState.AddError(error);

                                    // Else we have a fatal error and we need to change the behavior
                                    // since we want the complete error information in the exception.
                                    // Besides - no further results will be received.
                                    runBehavior = RunBehavior.UntilDone;
                                }
                            }
                        }
                        else if (error.Class >= TdsEnums.FATAL_ERROR_CLASS)
                        {
                            _tdsContext.TdsErrorWarningsState.AddError(error);
                        }
                        break;
                    }

                case TokenType.ColInfo:
                    {
                        break;
                        // TODO Add COLINFO TOKEN PARSER
                        //if (null != dataReader)
                        //{
                        //    _SqlMetaDataSet metaDataSet;
                        //    if (!TryProcessColInfo(dataStream.MetaData, dataStream, parserState, out metaDataSet))
                        //    {
                        //        return false;
                        //    }
                        //    if (!dataStream.TrySetMetaData(metaDataSet, false))
                        //    {
                        //        return false;
                        //    }
                        //    dataStream.BrowseModeInfoConsumed = true;
                        //}
                        //else
                        //{ // no dataStream
                        //    if (!parserState.TrySkipBytes(tokenLength))
                        //    {
                        //        return false;
                        //    }
                        //}
                        //break;
                    }

                case TokenType.Done:
                case TokenType.DoneProc:
                case TokenType.DoneInProc:
                    {
                        if ((token.Type == TokenType.DoneProc) && (cmdHandler != null))
                        {
                            // TODO Update SqlCommand with Error/Warnings from TdsContext

                            // If the current parse/read is for the results of describe parameter encryption RPC requests,
                            // call a different handler which will update the describe parameter encryption RPC structures
                            // with the results, instead of the actual user RPC requests.
                            //if (cmdHandler.IsDescribeParameterEncryptionRPCCurrentlyInProgress)
                            //{
                            //    cmdHandler.OnDoneDescribeParameterEncryptionProc(TdsContext);
                            //}
                            //else
                            //{
                            //    cmdHandler.OnDoneProc(parserState);
                            //}
                        }

                        break;
                    }

                case TokenType.Order:
                    {
                        // TODO Add parser to skip bytes if needed.
                        // don't do anything with the order token so read off the pipe
                        // await parserState.TdsStream.SkipReadBytesAsync(tokenLength, isAsync, ct).ConfigureAwait(false);
                        break;
                    }

                case TokenType.EnvChange:
                    {
                        while (token != null)
                        {
                            if (!_tdsContext.SqlConnector.OwningConnection.IgnoreEnvChange)
                            {
                                var envToken = (EnvChangeToken<long>)token;
                                switch (envToken.SubType)
                                {
                                    case EnvChangeTokenSubType.BeginTransaction:
                                    case EnvChangeTokenSubType.EnlistDtcTransaction:
                                        // When we get notification from the server of a new
                                        // transaction, we move any pending transaction over to
                                        // the current transaction, then we store the token in it.
                                        // if there isn't a pending transaction, then it's either
                                        // a TSQL transaction or a distributed transaction.
                                        Debug.Assert(null == _tdsContext.TdsTransactionState.CurrentTransaction, "non-null current transaction with an ENV Change");
                                        _tdsContext.TdsTransactionState.UpdateCurrentTransaction(_tdsContext.TdsTransactionState.PendingTransaction);
                                        _tdsContext.TdsTransactionState.UpdatePendingTransaction(null);

                                        if (null != _tdsContext.TdsTransactionState.CurrentTransaction)
                                        {
                                            _tdsContext.TdsTransactionState.CurrentTransaction.TransactionId = envToken.NewValue;   // this is defined as a ULongLong in the server and in the TDS Spec.
                                        }
                                        else
                                        {
                                            TransactionType transactionType = (EnvChangeTokenSubType.BeginTransaction == envToken.SubType) 
                                                ? TransactionType.LocalFromTSQL 
                                                : TransactionType.Distributed;
                                            // TODO Initialize SqlInternalTransaction
                                            // _tdsContext.TdsTransactionState.UpdateCurrentTransaction(new SqlInternalTransaction(_connHandler, transactionType, null, env._newLongValue));
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
                        if (!TryProcessLoginAck(parserState, out ack))
                        {
                            return false;
                        }

                        _connHandler.OnLoginAck(ack);
                        break;
                    }
                case TdsEnums.SQLFEDAUTHINFO:
                    {
                        _connHandler._federatedAuthenticationInfoReceived = true;
                        SqlFedAuthInfo info;

                        if (!TryProcessFedAuthInfo(parserState, tokenLength, out info))
                        {
                            return false;
                        }
                        _connHandler.OnFedAuthInfo(info);
                        break;
                    }
                case TdsEnums.SQLSESSIONSTATE:
                    {
                        if (!TryProcessSessionState(parserState, tokenLength, _connHandler._currentSessionData))
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
                            if (!TryProcessMetaData(tokenLength, parserState, out metadata, cmdHandler?.ColumnEncryptionSetting ?? SqlCommandColumnEncryptionSetting.UseConnectionSetting))
                            {
                                return false;
                            }
                            parserState._cleanupMetaData = metadata;
                        }
                        else
                        {
                            if (cmdHandler != null)
                            {
                                parserState._cleanupMetaData = cmdHandler.MetaData;
                            }
                        }

                        byte peekedToken;
                        if (!parserState.TryPeekByte(out peekedToken))
                        { // temporarily cache next byte
                            return false;
                        }

                        if (TdsEnums.SQLDATACLASSIFICATION == peekedToken)
                        {
                            byte dataClassificationToken;
                            if (!parserState.TryReadByte(out dataClassificationToken))
                            {
                                return false;
                            }
                            Debug.Assert(TdsEnums.SQLDATACLASSIFICATION == dataClassificationToken);

                            SensitivityClassification sensitivityClassification;
                            if (!TryProcessDataClassification(parserState, out sensitivityClassification))
                            {
                                return false;
                            }
                            if (null != dataStream && !dataStream.TrySetSensitivityClassification(sensitivityClassification))
                            {
                                return false;
                            }

                            // update peekedToken
                            if (!parserState.TryPeekByte(out peekedToken))
                            {
                                return false;
                            }
                        }

                        if (null != dataStream)
                        {
                            if (!dataStream.TrySetMetaData(parserState._cleanupMetaData, (TdsEnums.SQLTABNAME == peekedToken || TdsEnums.SQLCOLINFO == peekedToken)))
                            {
                                return false;
                            }
                        }
                        else if (null != bulkCopyHandler)
                        {
                            bulkCopyHandler.SetMetaData(parserState._cleanupMetaData);
                        }
                        break;
                    }
                case TdsEnums.SQLROW:
                case TdsEnums.SQLNBCROW:
                    {
                        Debug.Assert(parserState._cleanupMetaData != null, "Reading a row, but the metadata is null");

                        if (token == TdsEnums.SQLNBCROW)
                        {
                            if (!parserState.TryStartNewRow(isNullCompressed: true, nullBitmapColumnsCount: parserState._cleanupMetaData.Length))
                            {
                                return false;
                            }
                        }
                        else
                        {
                            if (!parserState.TryStartNewRow(isNullCompressed: false))
                            {
                                return false;
                            }
                        }

                        if (null != bulkCopyHandler)
                        {
                            if (!TryProcessRow(parserState._cleanupMetaData, bulkCopyHandler.CreateRowBuffer(), bulkCopyHandler.CreateIndexMap(), parserState))
                            {
                                return false;
                            }
                        }
                        else if (RunBehavior.ReturnImmediately != (RunBehavior.ReturnImmediately & runBehavior))
                        {
                            if (!TrySkipRow(parserState._cleanupMetaData, parserState))
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
                    if (!parserState.TryReadInt32(out status))
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
                        if (!TryProcessReturnValue(tokenLength, parserState, out returnValue, cmdHandler?.ColumnEncryptionSetting ?? SqlCommandColumnEncryptionSetting.UseConnectionSetting))
                        {
                            return false;
                        }
                        if (cmdHandler != null)
                        {
                            cmdHandler.OnReturnValue(returnValue, parserState);
                        }
                        break;
                    }
                case TdsEnums.SQLSSPI:
                    {
                        // token length is length of SSPI data - call ProcessSSPI with it

                        Debug.Assert(parserState._syncOverAsync, "ProcessSSPI does not support retry, do not attempt asynchronously");
                        parserState._syncOverAsync = true;

                        ProcessSSPI(tokenLength);
                        break;
                    }
                case TdsEnums.SQLTABNAME:
                    {
                        if (null != dataStream)
                        {
                            MultiPartTableName[] tableNames;
                            if (!TryProcessTableName(tokenLength, parserState, out tableNames))
                            {
                                return false;
                            }
                            dataStream.TableNames = tableNames;
                        }
                        else
                        {
                            await parserState.TdsStream.SkipReadBytesAsync(tokenLength, isAsync, ct).ConfigureAwait(false);
                        }
                        break;
                    }
                case TdsEnums.SQLRESCOLSRCS:
                    {
                        if (!TryProcessResColSrcs(parserState, tokenLength))
                        {
                            return false;
                        }
                        break;
                    }

                // deprecated
                case TdsEnums.SQLALTMETADATA:
                    {
                        parserState.CloneCleanupAltMetaDataSetArray();

                        if (parserState._cleanupAltMetaDataSetArray == null)
                        {
                            // create object on demand (lazy creation)
                            parserState._cleanupAltMetaDataSetArray = new _SqlMetaDataSetCollection();
                        }

                        _SqlMetaDataSet cleanupAltMetaDataSet;
                        if (!TryProcessAltMetaData(tokenLength, parserState, out cleanupAltMetaDataSet))
                        {
                            return false;
                        }

                        parserState._cleanupAltMetaDataSetArray.SetAltMetaData(cleanupAltMetaDataSet);
                        if (null != dataStream)
                        {
                            byte metadataConsumedByte;
                            if (!parserState.TryPeekByte(out metadataConsumedByte))
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
                        if (!parserState.TryStartNewRow(isNullCompressed: false))
                        { // altrows are not currently null compressed
                            return false;
                        }

                        // read will call run until dataReady. Must not read any data if ReturnImmediately set
                        if (RunBehavior.ReturnImmediately != (RunBehavior.ReturnImmediately & runBehavior))
                        {
                            ushort altRowId;
                            if (!parserState.TryReadUInt16(out altRowId))
                            { // get altRowId
                                return false;
                            }

                            if (!TrySkipRow(parserState._cleanupAltMetaDataSetArray.GetAltMetaData(altRowId), parserState))
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
                    break;
            }
        }


        private void OnTimeoutAsync(TimeoutState state)
        {
            if (_tdsContext.TimeoutState._enforceTimeoutDelay)
            {
                Thread.Sleep(_tdsContext.TimeoutState._enforcedTimeoutDelayInMilliSeconds);
            }

            int currentIdentityValue = _tdsContext.TimeoutState._timeoutIdentityValue;
            if (state.IdentityValue == _tdsContext.TimeoutState._timeoutIdentityValue)
            {
                // the return value is not useful here because no choice is going to be made using it 
                // we only want to make this call to set the state knowing that it will be seen later
                OnTimeoutCore(TimeoutState.Running, TimeoutState.ExpiredAsync);
            }
            else
            {
                Debug.WriteLine($"OnTimeoutAsync called with identity state={state.IdentityValue} but current identity is {currentIdentityValue} so it is being ignored");
            }
        }

        private bool OnTimeoutSync(bool asyncClose = false)
        {
            return OnTimeoutCore(TimeoutState.Running, TimeoutState.ExpiredSync, asyncClose);
        }

        /// <summary>
        /// attempts to change the timeout state from the expected state to the target state and if it succeeds
        /// will setup the parser state object into the timeout expired state
        /// </summary>
        /// <param name="expectedState">the state that is the expected current state, state will change only if this is correct</param>
        /// <param name="targetState">the state that will be changed to if the expected state is correct</param>
        /// <param name="asyncClose">any close action to be taken by an async task to avoid deadlock.</param>
        /// <returns>boolean value indicating whether the call changed the timeout state</returns>
        private bool OnTimeoutCore(int expectedState, int targetState, bool asyncClose = false)
        {
            Debug.Assert(targetState == TimeoutState.ExpiredAsync || targetState == TimeoutState.ExpiredSync, "OnTimeoutCore must have an expiry state as the targetState");

            bool retval = false;
            if (Interlocked.CompareExchange(ref _tdsContext.TimeoutState._timeoutState, targetState, expectedState) == expectedState)
            {
                retval = true;
                // lock protects against Close and Cancel
                lock (this)
                {
                    if (!_tdsContext.TimeoutState._attentionSent)
                    {
                        _tdsContext.TdsErrorWarningsState.AddError(new SqlError(TdsEnums.TIMEOUT_EXPIRED, 0x00, TdsEnums.MIN_ERROR_CLASS, _parser.Server, _parser.Connection.TimeoutErrorInternal.GetErrorMessage(), "", 0, TdsEnums.SNI_WAIT_TIMEOUT));

                        // TODO Support sending Attention
                        //// Grab a reference to the _networkPacketTaskSource in case it becomes null while we are trying to use it
                        //TaskCompletionSource<object> source = _networkPacketTaskSource;

                        //if (_parser.Connection.IsInPool)
                        //{
                        //    // We should never timeout if the connection is currently in the pool: the safest thing to do here is to doom the connection to avoid corruption
                        //    Debug.Assert(_parser.Connection.IsConnectionDoomed, "Timeout occurred while the connection is in the pool");
                        //    _parser.State = TdsParserState.Broken;
                        //    _parser.Connection.BreakConnection();
                        //    if (source != null)
                        //    {
                        //        source.TrySetCanceled();
                        //    }
                        //}
                        //else if (_parser.State == TdsParserState.OpenLoggedIn)
                        //{
                        //    try
                        //    {
                        //        SendAttention(mustTakeWriteLock: true, asyncClose);
                        //    }
                        //    catch (Exception e)
                        //    {
                        //        if (!ADP.IsCatchableExceptionType(e))
                        //        {
                        //            throw;
                        //        }
                        //        // if unable to send attention, cancel the _networkPacketTaskSource to
                        //        // request the parser be broken.  SNIWritePacket errors will already
                        //        // be in the _errors collection.
                        //        if (source != null)
                        //        {
                        //            source.TrySetCanceled();
                        //        }
                        //    }
                        //}

                        //// If we still haven't received a packet then we don't want to actually close the connection
                        //// from another thread, so complete the pending operation as cancelled, informing them to break it
                        //if (source != null)
                        //{
                        //    Task.Delay(AttentionTimeoutSeconds * 1000).ContinueWith(_ =>
                        //    {
                        //        // Only break the connection if the read didn't finish
                        //        if (!source.Task.IsCompleted)
                        //        {
                        //            int pendingCallback = IncrementPendingCallbacks();
                        //            RuntimeHelpers.PrepareConstrainedRegions();
                        //            try
                        //            {
                        //                // If pendingCallback is at 3, then ReadAsyncCallback hasn't been called yet
                        //                // So it is safe for us to break the connection and cancel the Task (since we are not sure that ReadAsyncCallback will ever be called)
                        //                if ((pendingCallback == 3) && (!source.Task.IsCompleted))
                        //                {
                        //                    Debug.Assert(source == _networkPacketTaskSource, "_networkPacketTaskSource which is being timed is not the current task source");

                        //                    // Try to throw the timeout exception and store it in the task
                        //                    bool exceptionStored = false;
                        //                    try
                        //                    {
                        //                        CheckThrowSNIException();
                        //                    }
                        //                    catch (Exception ex)
                        //                    {
                        //                        if (source.TrySetException(ex))
                        //                        {
                        //                            exceptionStored = true;
                        //                        }
                        //                    }

                        //                    // Ensure that the connection is no longer usable
                        //                    // This is needed since the timeout error added above is non-fatal (and so throwing it won't break the connection)
                        //                    _parser.State = TdsParserState.Broken;
                        //                    _parser.Connection.BreakConnection();

                        //                    // If we didn't get an exception (something else observed it?) then ensure that the task is cancelled
                        //                    if (!exceptionStored)
                        //                    {
                        //                        source.TrySetCanceled();
                        //                    }
                        //                }
                        //            }
                        //            finally
                        //            {
                        //                DecrementPendingCallbacks(release: false);
                        //            }
                        //        }
                        //    });
                        //}
                    }
                }
            }
            return retval;
        }
    }
}
#endif

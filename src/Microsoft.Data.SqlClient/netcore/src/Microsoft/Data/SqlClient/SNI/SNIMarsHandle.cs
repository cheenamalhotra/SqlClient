// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace Microsoft.Data.SqlClient.SNI
{
    /// <summary>
    /// MARS handle
    /// </summary>
    internal sealed class SNIMarsHandle : SNIHandle
    {
        private const uint ACK_THRESHOLD = 2;

        private readonly SNIMarsConnection _connection;
        private readonly uint _status = TdsEnums.SNI_UNINITIALIZED;
        private readonly Queue<SNIPacket> _receivedPacketQueue = new Queue<SNIPacket>();
        private readonly Queue<SNIMarsQueuedPacket> _sendPacketQueue = new Queue<SNIMarsQueuedPacket>();
        private readonly object _callbackObject;
        private readonly Guid _connectionId;
        private readonly ushort _sessionId;
        private readonly ManualResetEventSlim _packetEvent = new ManualResetEventSlim(false);
        private readonly ManualResetEventSlim _ackEvent = new ManualResetEventSlim(false);
        private readonly SNISMUXHeader _currentHeader = new SNISMUXHeader();
        private readonly SNIAsyncCallback _handleSendCompleteCallback;

        private uint _sendHighwater = 4;
        private int _asyncReceives = 0;
        private uint _receiveHighwater = 4;
        private uint _receiveHighwaterLastAck = 4;
        private uint _sequenceNumber;
        private SNIError _connectionError;

        /// <summary>
        /// Connection ID
        /// </summary>
        public override Guid ConnectionId => _connectionId;

        /// <summary>
        /// Handle status
        /// </summary>
        public override uint Status => _status;

        public override int ReserveHeaderSize => SNISMUXHeader.HEADER_LENGTH;

        public override int ProtocolVersion => _connection.ProtocolVersion;

        /// <summary>
        /// Dispose object
        /// </summary>
        public override void Dispose()
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.Dispose | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                SendControlPacket(SNISMUXFlags.SMUX_FIN);
                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Dispose | SNI | INFO | MARS Session Id {0}, Sent SMUX_FIN packet to terminate session.", ConnectionId);
            }
            catch (Exception e)
            {
                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Dispose | SNI | ERR | MARS Session Id {0}, Internal exception error = {1}, Member Name={2}", ConnectionId, e?.Message, e?.GetType()?.Name);
                SNICommon.ReportSNIError(SNIProviders.SMUX_PROV, SNICommon.InternalExceptionError, e);
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="connection">MARS connection</param>
        /// <param name="sessionId">MARS session ID</param>
        /// <param name="callbackObject">Callback object</param>
        /// <param name="async">true if connection is asynchronous</param>
        public SNIMarsHandle(SNIMarsConnection connection, ushort sessionId, object callbackObject, bool async)
        {
            _sessionId = sessionId;
            _connection = connection;
            _connectionId = connection.ConnectionId;
            _callbackObject = callbackObject;
            _handleSendCompleteCallback = HandleSendComplete;
            SendControlPacket(SNISMUXFlags.SMUX_SYN);
            SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.ctor | SNI | INFO | MARS Session Id {0}, Sent SMUX_SYN packet to start a new session, session Id {1}", ConnectionId, _sessionId);
            _status = TdsEnums.SNI_SUCCESS;
        }

        /// <summary>
        /// Send control packet
        /// </summary>
        /// <param name="flags">SMUX header flags</param>
        private void SendControlPacket(SNISMUXFlags flags)
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.SendControlPacket | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                SNIPacket packet = RentPacket(headerSize: SNISMUXHeader.HEADER_LENGTH, dataSize: 0);
#if DEBUG
                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.SendControlPacket | SNI | INFO | MARS Session Id {0}, Packet rented {1}, packet dataLeft {2}", ConnectionId, packet?._id, packet?.DataLeft);
#endif
                lock (this)
                {
                    SetupSMUXHeader(0, flags);
                    _currentHeader.Write(packet.GetHeaderBuffer(SNISMUXHeader.HEADER_LENGTH));
                    packet.SetHeaderActive();
                }

                _connection.Send(packet);
                ReturnPacket(packet);
#if DEBUG
                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.SendControlPacket | SNI | INFO | MARS Session Id {0}, Packet returned {1}, packet dataLeft {2}", ConnectionId, packet?._id, packet?.DataLeft);
#endif
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        private void SetupSMUXHeader(int length, SNISMUXFlags flags)
        {
            Debug.Assert(Monitor.IsEntered(this), "must take lock on self before updating smux header");

            _currentHeader.SMID = 83;
            _currentHeader.flags = (byte)flags;
            _currentHeader.sessionId = _sessionId;
            _currentHeader.length = (uint)SNISMUXHeader.HEADER_LENGTH + (uint)length;
            _currentHeader.sequenceNumber = ((flags == SNISMUXFlags.SMUX_FIN) || (flags == SNISMUXFlags.SMUX_ACK)) ? _sequenceNumber - 1 : _sequenceNumber++;
            _currentHeader.highwater = _receiveHighwater;
            _receiveHighwaterLastAck = _currentHeader.highwater;
        }

        /// <summary>
        /// Generate a packet with SMUX header
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <returns>The packet with the SMUx header set.</returns>
        private SNIPacket SetPacketSMUXHeader(SNIPacket packet)
        {
            Debug.Assert(packet.ReservedHeaderSize == SNISMUXHeader.HEADER_LENGTH, "mars handle attempting to smux packet without smux reservation");

            SetupSMUXHeader(packet.Length, SNISMUXFlags.SMUX_DATA);
            _currentHeader.Write(packet.GetHeaderBuffer(SNISMUXHeader.HEADER_LENGTH));
            packet.SetHeaderActive();
#if DEBUG
            SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.SetPacketSMUXHeader | SNI | INFO | MARS Session Id {0}, Setting SMUX_DATA header in current header for packet {1}", ConnectionId, packet?._id);
#endif
            return packet;
        }

        /// <summary>
        /// Send a packet synchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <returns>SNI error code</returns>
        public override uint Send(SNIPacket packet)
        {
            Debug.Assert(packet.ReservedHeaderSize == SNISMUXHeader.HEADER_LENGTH, "mars handle attempting to send muxed packet without smux reservation in Send");
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.Send | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                while (true)
                {
                    lock (this)
                    {
                        if (_sequenceNumber < _sendHighwater)
                        {
                            break;
                        }
                    }

                    SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Send | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, Waiting for Acknowledgment event.", ConnectionId, _sequenceNumber, _sendHighwater);
                    _ackEvent.Wait();

                    lock (this)
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.SendPendingPackets | SNI | INFO | MARS Session Id {0}, _sendPacketQueue count found {1}, Acknowledgment event Reset", ConnectionId, _sendPacketQueue?.Count);
                        _ackEvent.Reset();
                    }
                }

                SNIPacket muxedPacket = null;
                lock (this)
                {
                    muxedPacket = SetPacketSMUXHeader(packet);
                }
                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Send | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, SMUX Packet is going to be sent.", ConnectionId, _sequenceNumber, _sendHighwater);
                return _connection.Send(muxedPacket);
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Send packet asynchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <param name="callback">Completion callback</param>
        /// <returns>SNI error code</returns>
        private uint InternalSendAsync(SNIPacket packet, SNIAsyncCallback callback)
        {
            Debug.Assert(packet.ReservedHeaderSize == SNISMUXHeader.HEADER_LENGTH, "mars handle attempting to send muxed packet without smux reservation in InternalSendAsync");
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.InternalSendAsync | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                lock (this)
                {
                    if (_sequenceNumber >= _sendHighwater)
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.InternalSendAsync | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, SNI Queue is full", ConnectionId, _sequenceNumber, _sendHighwater);
                        return TdsEnums.SNI_QUEUE_FULL;
                    }

                    SNIPacket muxedPacket = SetPacketSMUXHeader(packet);
                    muxedPacket.SetCompletionCallback(callback ?? HandleSendComplete);
                    SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.InternalSendAsync | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, Sending packet", ConnectionId, _sequenceNumber, _sendHighwater);
                    return _connection.SendAsync(muxedPacket, callback);
                }
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Send pending packets
        /// </summary>
        /// <returns>SNI error code</returns>
        private uint SendPendingPackets()
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.SendPendingPackets | SNI | INFO | SCOPE | Entering Scope {0}");
            SNIMarsQueuedPacket packet = null;
            try
            {
                while (true)
                {
                    lock (this)
                    {
                        if (_sequenceNumber < _sendHighwater)
                        {
                            if (_sendPacketQueue.Count != 0)
                            {
                                packet = _sendPacketQueue.Peek();
                                uint result = InternalSendAsync(packet.Packet, packet.Callback);

                                if (result != TdsEnums.SNI_SUCCESS && result != TdsEnums.SNI_SUCCESS_IO_PENDING)
                                {
                                    SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.SendPendingPackets | SNI | ERR | MARS Session Id {0}, InternalSendAsync result is not SNI_SUCCESS and is not SNI_SUCCESS_IO_PENDING", ConnectionId);
                                    return result;
                                }

                                _sendPacketQueue.Dequeue();
                                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.SendPendingPackets | SNI | INFO | MARS Session Id {0}, _sendPacketQueue dequeued, count {1}", ConnectionId, _sendPacketQueue?.Count);
                                continue;
                            }
                            else
                            {
                                _ackEvent.Set();
                                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.SendPendingPackets | SNI | INFO | MARS Session Id {0}, _sendPacketQueue count found {1}, acknowledgment set", ConnectionId, _sendPacketQueue?.Count);
                            }
                        }

                        break;
                    }
                }

                return TdsEnums.SNI_SUCCESS;
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Send a packet asynchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <param name="callback">Completion callback</param>
        /// <returns>SNI error code</returns>
        public override uint SendAsync(SNIPacket packet, SNIAsyncCallback callback = null)
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.SendAsync | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                lock (this)
                {
                    _sendPacketQueue.Enqueue(new SNIMarsQueuedPacket(packet, callback ?? _handleSendCompleteCallback));
                }

                SendPendingPackets();
                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.SendAsync | SNI | INFO | MARS Session Id {0}, _sendPacketQueue enqueued, count {1}", ConnectionId, _sendPacketQueue?.Count);

                return TdsEnums.SNI_SUCCESS_IO_PENDING;
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Receive a packet asynchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <returns>SNI error code</returns>
        public override uint ReceiveAsync(ref SNIPacket packet)
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.ReceiveAsync | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                lock (_receivedPacketQueue)
                {
                    int queueCount = _receivedPacketQueue.Count;

                    if (_connectionError != null)
                    {
                        SqlClientEventSource.Log.TryTraceEvent("SNIMarsHandle.ReceiveAsync | SNI | ERR | MARS Session Id {0}, _asyncReceives {1}, _receiveHighwater {2}, _sendHighwater {3}, _receiveHighwaterLastAck {4}, _connectionError {5}", ConnectionId, _asyncReceives, _receiveHighwater, _sendHighwater, _receiveHighwaterLastAck, _connectionError);
                        return SNICommon.ReportSNIError(_connectionError);
                    }

                    if (queueCount == 0)
                    {
                        _asyncReceives++;
                        SqlClientEventSource.Log.TryTraceEvent("SNIMarsHandle.ReceiveAsync | SNI | Info | MARS Session Id {0}, queueCount 0, _asyncReceives {1}, _receiveHighwater {2}, _sendHighwater {3}, _receiveHighwaterLastAck {4}", ConnectionId, _asyncReceives, _receiveHighwater, _sendHighwater, _receiveHighwaterLastAck);

                        return TdsEnums.SNI_SUCCESS_IO_PENDING;
                    }

                    packet = _receivedPacketQueue.Dequeue();

                    if (queueCount == 1)
                    {
#if DEBUG
                        SqlClientEventSource.Log.TryTraceEvent("SNIMarsHandle.ReceiveAsync | SNI | Info | MARS Session Id {0}, packet dequeued {1}, packet Owner {2}, packet refCount {3}, received Packet Queue count {4}", ConnectionId, packet?._id, packet?._owner, packet?._refCount, _receivedPacketQueue?.Count);
#endif
                        _packetEvent.Reset();
                    }
                }

                lock (this)
                {
                    _receiveHighwater++;
                }

                SqlClientEventSource.Log.TryTraceEvent("SNIMarsHandle.ReceiveAsync | Info | MARS Session Id {0}, _asyncReceives {1}, _receiveHighwater {2}, _sendHighwater {3}, _receiveHighwaterLastAck {4}, queueCount {5}", ConnectionId, _asyncReceives, _receiveHighwater, _sendHighwater, _receiveHighwaterLastAck, _receivedPacketQueue?.Count);
                SendAckIfNecessary();
                return TdsEnums.SNI_SUCCESS;
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Handle receive error
        /// </summary>
        public void HandleReceiveError(SNIPacket packet)
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.HandleReceiveError | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                // SNIMarsHandle should only receive calls to this function from the SNIMarsConnection aggregator class
                // which should handle ownership of the packet because the individual mars handles are not aware of
                // each other and cannot know if they are the last one in the list and that it is safe to return the packet

                lock (_receivedPacketQueue)
                {
                    _connectionError = SNILoadHandle.SingletonInstance.LastError;
                    SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.HandleReceiveError | SNI | ERR | MARS Session Id {0}, _connectionError to be handled: {1}", ConnectionId, _connectionError);
                    _packetEvent.Set();
                }

                ((TdsParserStateObject)_callbackObject).ReadAsyncCallback(PacketHandle.FromManagedPacket(packet), 1);
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Handle send completion
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <param name="sniErrorCode">SNI error code</param>
        public void HandleSendComplete(SNIPacket packet, uint sniErrorCode)
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.HandleSendComplete | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                lock (this)
                {
                    Debug.Assert(_callbackObject != null);

                    ((TdsParserStateObject)_callbackObject).WriteAsyncCallback(PacketHandle.FromManagedPacket(packet), sniErrorCode);
                }
                _connection.ReturnPacket(packet);
#if DEBUG
                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.HandleSendComplete | SNI | INFO | MARS Session Id {0}, Returned Packet: {1}", ConnectionId, packet?._id);
#endif
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Handle SMUX acknowledgment
        /// </summary>
        /// <param name="highwater">Send highwater mark</param>
        public void HandleAck(uint highwater)
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.HandleAck | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                lock (this)
                {
                    if (_sendHighwater != highwater)
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.HandleAck | SNI | INFO | MARS Session Id {0}, Setting _sendHighwater {1} to highwater {2} and send pending packets.", ConnectionId, _sendHighwater, highwater);
                        _sendHighwater = highwater;
                        SendPendingPackets();
                    }
                }
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Handle receive completion
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <param name="header">SMUX header</param>
        public void HandleReceiveComplete(SNIPacket packet, SNISMUXHeader header)
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.HandleReceiveComplete | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                lock (this)
                {
                    if (_sendHighwater != header.highwater)
                    {
                        SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.HandleReceiveComplete | SNI | INFO | MARS Session Id {0}, header.highwater {1}, _sendHighwater {2}, Handle Ack with header.highwater", ConnectionId, header.highwater, _sendHighwater);
                        HandleAck(header.highwater);
                    }

                    lock (_receivedPacketQueue)
                    {
                        if (_asyncReceives == 0)
                        {
                            _receivedPacketQueue.Enqueue(packet);
                            _packetEvent.Set();
                            SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.HandleReceiveComplete | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, _receivedPacketQueue count {3}, packet event set", ConnectionId, _sequenceNumber, _sendHighwater, _receivedPacketQueue.Count);
                            return;
                        }

                        _asyncReceives--;
                        Debug.Assert(_callbackObject != null);
                        SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.HandleReceiveComplete | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, _asyncReceives {3}", ConnectionId, _sequenceNumber, _sendHighwater, _asyncReceives);

                        ((TdsParserStateObject)_callbackObject).ReadAsyncCallback(PacketHandle.FromManagedPacket(packet), 0);
                    }

                    _connection.ReturnPacket(packet);
                }

                lock (this)
                {
                    _receiveHighwater++;
                }
                SqlClientEventSource.Log.TryTraceEvent("SNIMarsHandle.HandleReceiveComplete | Info | MARS Session Id {0}, _asyncReceives {1}, _receiveHighwater {2}, _sendHighwater {3}, _receiveHighwaterLastAck {4}", ConnectionId, _asyncReceives, _receiveHighwater, _sendHighwater, _receiveHighwaterLastAck);
                SendAckIfNecessary();
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Send ACK if we've hit highwater threshold
        /// </summary>
        private void SendAckIfNecessary()
        {
            uint receiveHighwater;
            uint receiveHighwaterLastAck;

            lock (this)
            {
                receiveHighwater = _receiveHighwater;
                receiveHighwaterLastAck = _receiveHighwaterLastAck;
            }

            if (receiveHighwater - receiveHighwaterLastAck > ACK_THRESHOLD)
            {
                SendControlPacket(SNISMUXFlags.SMUX_ACK);
                SqlClientEventSource.Log.TryTraceEvent("SNIMarsHandle.SendAckIfNecessary | Info | MARS Session Id {0}, _asyncReceives {1}, _receiveHighwater {2}, _sendHighwater {3}, _receiveHighwaterLastAck {4} Sending acknowledgment > ACK_THRESHOLD {5}", ConnectionId, _asyncReceives, _receiveHighwater, _sendHighwater, _receiveHighwaterLastAck, ACK_THRESHOLD);
            }
        }

        /// <summary>
        /// Receive a packet synchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <param name="timeoutInMilliseconds">Timeout in Milliseconds</param>
        /// <returns>SNI error code</returns>
        public override uint Receive(out SNIPacket packet, int timeoutInMilliseconds)
        {
            long scopeID = SqlClientEventSource.Log.TrySNIScopeEnterEvent("SNIMarsHandle.Receive | SNI | INFO | SCOPE | Entering Scope {0}");
            try
            {
                packet = null;
                int queueCount;
                uint result = TdsEnums.SNI_SUCCESS_IO_PENDING;

                while (true)
                {
                    lock (_receivedPacketQueue)
                    {
                        if (_connectionError != null)
                        {
                            SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Receive | SNI | ERR | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, _connectionError found: {3}.", ConnectionId, _sequenceNumber, _sendHighwater, _connectionError);
                            return SNICommon.ReportSNIError(_connectionError);
                        }

                        queueCount = _receivedPacketQueue.Count;
                        SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Receive | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, W_receivedPacketQueue count {3}.", ConnectionId, _sequenceNumber, _sendHighwater, queueCount);

                        if (queueCount > 0)
                        {
                            packet = _receivedPacketQueue.Dequeue();

                            if (queueCount == 1)
                            {
                                _packetEvent.Reset();
                                SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Receive | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, packet event reset, _receivedPacketQueue count 1.", ConnectionId, _sequenceNumber, _sendHighwater);
                            }

                            result = TdsEnums.SNI_SUCCESS;
                        }
                    }

                    if (result == TdsEnums.SNI_SUCCESS)
                    {
                        lock (this)
                        {
                            _receiveHighwater++;
                        }

                        SendAckIfNecessary();
                        SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Receive | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, returning with result {3}.", ConnectionId, _sequenceNumber, _sendHighwater, result);
                        return result;
                    }

                    SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Receive | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, Waiting for packet event.", ConnectionId, _sequenceNumber, _sendHighwater);
                    if (!_packetEvent.Wait(timeoutInMilliseconds))
                    {
                        SNILoadHandle.SingletonInstance.LastError = new SNIError(SNIProviders.SMUX_PROV, 0, SNICommon.ConnTimeoutError, Strings.SNI_ERROR_11);
                        SqlClientEventSource.Log.TrySNITraceEvent("SNIMarsHandle.Receive | SNI | INFO | MARS Session Id {0}, _sequenceNumber {1}, _sendHighwater {2}, _packetEvent wait timed out.", ConnectionId, _sequenceNumber, _sendHighwater);
                        return TdsEnums.SNI_WAIT_TIMEOUT;
                    }
                }
            }
            finally
            {
                SqlClientEventSource.Log.TrySNIScopeLeaveEvent(scopeID);
            }
        }

        /// <summary>
        /// Check SNI handle connection
        /// </summary>
        /// <returns>SNI error status</returns>
        public override uint CheckConnection()
        {
            return _connection.CheckConnection();
        }

        /// <summary>
        /// Set async callbacks
        /// </summary>
        /// <param name="receiveCallback">Receive callback</param>
        /// <param name="sendCallback">Send callback</param>
        public override void SetAsyncCallbacks(SNIAsyncCallback receiveCallback, SNIAsyncCallback sendCallback)
        {
        }

        /// <summary>
        /// Set buffer size
        /// </summary>
        /// <param name="bufferSize">Buffer size</param>
        public override void SetBufferSize(int bufferSize)
        {
        }

        public override uint EnableSsl(uint options) => _connection.EnableSsl(options);

        public override void DisableSsl() => _connection.DisableSsl();

        public override SNIPacket RentPacket(int headerSize, int dataSize) => _connection.RentPacket(headerSize, dataSize);

        public override void ReturnPacket(SNIPacket packet) => _connection.ReturnPacket(packet);


#if DEBUG
        /// <summary>
        /// Test handle for killing underlying connection
        /// </summary>
        public override void KillConnection()
        {
            _connection.KillConnection();
        }
#endif
    }
}

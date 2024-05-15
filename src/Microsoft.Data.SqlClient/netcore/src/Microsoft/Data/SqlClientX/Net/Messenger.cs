// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClientX.Net.Types;

namespace Microsoft.Data.SqlClientX.Net
{
    internal abstract class Messenger : IAsyncDisposable
    {
        protected const int DefaultPoolSize = 4;

#if DEBUG
        private static int s_packetId;
#endif
        private SqlObjectPool<Packet> _pool;

        protected static readonly SslProtocols s_supportedProtocols = SslProtocols.None;

        protected static readonly List<SslApplicationProtocol> s_tdsProtocols = new(1) { new(TdsEnums.TDS8_Protocol) };

        public Messenger(int poolSize = DefaultPoolSize)
        {
            _pool = new SqlObjectPool<Packet>(poolSize);
        }

        protected static async Task AuthenticateAsClientAsync(SslStream sslStream, string serverNameIndication, X509CertificateCollection certificate, CancellationToken token)
            => await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions()
            {
                TargetHost = serverNameIndication,
                ApplicationProtocols = s_tdsProtocols,
                ClientCertificates = certificate
            }, token).ConfigureAwait(false);

        /// <summary>
        /// Dispose all resources asynchronously
        /// </summary>
        /// <returns></returns>
        public abstract ValueTask DisposeAsync();

        /// <summary>
        /// Send a packet asynchronously
        /// </summary>
        /// <param name="packet">SNI packet</param>
        /// <param name="async">Whether this is called by an Async API</param>
        /// <param name="cancellationToken">Cancellation Token</param>
        /// <returns>SNI error code</returns>
        public abstract ValueTask<uint> SendAsync(Packet packet, bool async, CancellationToken cancellationToken);

        /// <summary>
        /// Receive a packet asynchronously
        /// </summary>
        /// <param name="async">Whether this is called by an Async API</param>
        /// <param name="cancellationToken">Cancellation Token</param>
        /// <returns>SNI error code</returns>
        public abstract ValueTask<Message> ReceiveAsync(bool async, CancellationToken cancellationToken);

        /// <summary>
        /// Enable SSL
        /// </summary>
        public abstract ValueTask<uint> EnableSslAsync(uint options);

        /// <summary>
        /// Disable SSL
        /// </summary>
        public abstract Task DisableSslAsync();

        /// <summary>
        /// Check connection status
        /// </summary>
        /// <returns>SNI error code</returns>
        public abstract uint CheckConnection();

        /// <summary>
        /// Set buffer size
        /// </summary>
        /// <param name="bufferSize">Buffer size</param>
        public abstract void SetBufferSize(int bufferSize);

        /// <summary>
        /// Last handle status
        /// </summary>
        public abstract uint Status { get; }

        /// <summary>
        /// Connection ID
        /// </summary>
        public abstract Guid ConnectionId { get; }

        public virtual int ReserveHeaderSize => 0;

        /// <summary>
        /// Gets a value that indicates the security protocol used to authenticate this connection.
        /// </summary>
        public virtual int ProtocolVersion { get; } = 0;
#if DEBUG
        /// <summary>
        /// Test handle for killing underlying connection
        /// </summary>
        public abstract void KillConnection();
#endif

        public Packet RentPacket(int headerSize, int dataSize)
        {
            if (!_pool.TryGet(out Packet packet))
            {
#if DEBUG
                int id = Interlocked.Increment(ref s_packetId);
                packet = new Packet(this, id);
#else
                packet = new Packet();
#endif
            }
#if DEBUG
            else
            {
                Debug.Assert(packet != null, "dequeue returned null Packet");
                Debug.Assert(!packet.IsActive, "Packet _refcount must be 1 or a lifetime issue has occurred, trace with the #TRACE_HISTORY define");
                Debug.Assert(packet.IsInvalid, "dequeue returned valid packet");
                GC.ReRegisterForFinalize(packet);
            }
#if TRACE_HISTORY
            if (packet._history != null)
            {
                packet._history.Add(new Packet.History { Action = Packet.History.Direction.Rent, Stack = GetStackParts(), RefCount = packet._refCount });
            }
#endif
            Interlocked.Add(ref packet._refCount, 1);
            Debug.Assert(packet.IsActive, "Packet _refcount must be 1 or a lifetime issue has occurred, trace with the #TRACE_HISTORY define");
#endif
            packet.Allocate(headerSize, dataSize);
            return packet;
        }

        public void ReturnPacket(Packet packet)
        {
#if DEBUG
            Debug.Assert(packet != null, "releasing null Packet");
            Debug.Assert(packet.IsActive, "Packet _refcount must be 1 or a lifetime issue has occurred, trace with the #TRACE_HISTORY define");
            Debug.Assert(ReferenceEquals(packet._messenger, this), "releasing Packet that belongs to another physical handle");
            Debug.Assert(!packet.IsInvalid, "releasing already released Packet");
#endif

            packet.Release();
#if DEBUG
            Interlocked.Add(ref packet._refCount, -1);
            packet._traceTag = null;
#if TRACE_HISTORY
            if (packet._history != null)
            {
                packet._history.Add(new Packet.History { Action = Packet.History.Direction.Return, Stack = GetStackParts(), RefCount = packet._refCount });
            }
#endif
            GC.SuppressFinalize(packet);
#endif
            _pool.Return(packet);
        }

#if DEBUG && TRACE_HISTORY
        private static string GetStackParts()
        {
            // trims off the common parts at the top of the stack so you can see what the actual caller was
            // trims off most of the bottom of the stack because when running under xunit there's a lot of spam
            string[] parts = Environment.StackTrace.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);
            List<string> take = new List<string>(7);
            for (int index = 3; take.Count < 7 && index < parts.Length; index++)
            {
                take.Add(parts[index]);
            }

            return string.Join(Environment.NewLine, take.ToArray());
        }
#endif
    }
}

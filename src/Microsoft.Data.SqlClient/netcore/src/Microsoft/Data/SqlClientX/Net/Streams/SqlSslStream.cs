﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Net.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClientX.Net.Types;

namespace Microsoft.Data.SqlClientX.Net.Streams
{
    /// <summary>
    /// This class extends SslStream to customize stream behavior for Managed networking implementation.
    /// </summary>
    internal sealed partial class SqlSslStream : SslStream
    {
        private readonly ConcurrentQueueSemaphore _writeAsyncSemaphore;
        private readonly ConcurrentQueueSemaphore _readAsyncSemaphore;

        public SqlSslStream(Stream innerStream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback userCertificateValidationCallback)
            : base(innerStream, leaveInnerStreamOpen, userCertificateValidationCallback)
        {
            _writeAsyncSemaphore = new ConcurrentQueueSemaphore(1);
            _readAsyncSemaphore = new ConcurrentQueueSemaphore(1);
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return ReadAsync(new Memory<byte>(buffer, offset, count), cancellationToken).AsTask();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await _readAsyncSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                return await base.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SqlSslStream), EventType.ERR, "Internal Exception occurred while reading data: {0}", args0: e?.Message);
                throw;
            }
            finally
            {
                _readAsyncSemaphore.Release();
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return WriteAsync(new Memory<byte>(buffer, offset, count), cancellationToken).AsTask();
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await _writeAsyncSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                await base.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                SqlClientEventSource.Log.TrySNITraceEvent(nameof(SqlSslStream), EventType.ERR, "Internal Exception occurred while reading data: {0}", args0: e?.Message);
                throw;
            }
            finally
            {
                _writeAsyncSemaphore.Release();
            }
        }
    }
}

﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Net.Security;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;

namespace Microsoft.Data.SqlClient.SNI
{
    /// <summary>
    /// This class extends SslStream to customize stream behavior for Managed SNI implementation.
    /// </summary>
    internal class SNISslStream : SslStream
    {
        private readonly SemaphoreSlim _writeAsyncQueueSemaphore;
        private readonly SemaphoreSlim _readAsyncQueueSemaphore;

        public SNISslStream(Stream innerStream, bool leaveInnerStreamOpen, RemoteCertificateValidationCallback userCertificateValidationCallback)
            : base(innerStream, leaveInnerStreamOpen, userCertificateValidationCallback)
        {
            _writeAsyncQueueSemaphore = new SemaphoreSlim(1);
            _readAsyncQueueSemaphore = new SemaphoreSlim(1);
        }

        // Prevent ReadAsync collisions by running the task in a Semaphore Slim
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await _readAsyncQueueSemaphore.WaitAsync().ConfigureAwait(false);
            try
            {
                return await base.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _readAsyncQueueSemaphore.Release();
            }
        }

        // Prevent the WriteAsync collisions by running the task in a Semaphore Slim
        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await _writeAsyncQueueSemaphore.WaitAsync().ConfigureAwait(false);
            try
            {
                await base.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeAsyncQueueSemaphore.Release();
            }
        }
    }

    /// <summary>
    /// This class extends NetworkStream to customize stream behavior for Managed SNI implementation.
    /// </summary>
    internal class SNINetworkStream : NetworkStream
    {
        private readonly SemaphoreSlim _writeAsyncQueueSemaphore;
        private readonly SemaphoreSlim _readAsyncQueueSemaphore;

        public SNINetworkStream(Socket socket, bool ownsSocket) : base(socket, ownsSocket)
        {
            _writeAsyncQueueSemaphore = new SemaphoreSlim(1);
            _readAsyncQueueSemaphore = new SemaphoreSlim(1);
        }

        // Prevent the ReadAsync collisions by running the task in a Semaphore Slim
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await _readAsyncQueueSemaphore.WaitAsync().ConfigureAwait(false);
            try
            {
                return await base.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _readAsyncQueueSemaphore.Release();
            }
        }

        // Prevent the WriteAsync collisions by running the task in a Semaphore Slim
        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await _writeAsyncQueueSemaphore.WaitAsync().ConfigureAwait(false);
            try
            {
                await base.WriteAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeAsyncQueueSemaphore.Release();
            }
        }
    }
}

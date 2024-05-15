// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Threading.Tasks;
using Microsoft.Data.SqlClientX.Net.Types;
using Microsoft.Data.SqlClientX.Logging;
using Microsoft.Data.SqlClientX.Net;
using System.Threading;

namespace Microsoft.Data.SqlClientX.TDS.Handlers
{
    // NetworkHandler Implementation
    internal class NetworkHandler : INetworkHandler
    {
        private readonly Messenger _messenger;
        private readonly ILogger _logger;

        public NetworkHandler(Messenger messenger, ILogger logger)
        {
            _messenger = messenger;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async ValueTask ProcessPacketAsync(Packet packet)
        {
            // Asynchronous packet processing logic
        }

        public async ValueTask<Message> ReadNetworkPacketAsync(bool async, CancellationToken cancellationToken)
        {
            // Asynchronous network packet reading logic
            return await _messenger.ReceiveAsync(async, cancellationToken);
        }
    }
}

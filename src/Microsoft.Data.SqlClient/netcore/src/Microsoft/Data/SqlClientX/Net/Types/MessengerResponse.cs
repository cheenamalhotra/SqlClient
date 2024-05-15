// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Net.Sockets;

namespace Microsoft.Data.SqlClientX.Net.Types
{
    internal class MessengerResponse
    {
        internal readonly Socket _socket;
        internal bool _reportOnError;

        public MessengerResponse(Socket socket, bool reportOnError)
        {
            _socket = socket;
            _reportOnError = reportOnError;
        }
    }
}

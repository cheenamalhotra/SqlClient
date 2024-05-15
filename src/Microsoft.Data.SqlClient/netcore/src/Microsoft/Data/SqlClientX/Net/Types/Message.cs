// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace Microsoft.Data.SqlClientX.Net.Types
{
    internal class Message
    {
        internal uint responseCode;
        internal Packet packet;

        public Message(uint responseCode, Packet packet)
        {
            this.responseCode = responseCode;
            this.packet = packet;
        }
    }
}

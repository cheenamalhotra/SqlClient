// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET6_0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

#nullable enable

namespace Microsoft.Data.SqlClientX.Net.Security
{
    internal sealed class SspiClientContextProvider : SSPIContextProvider
    {
        private SspiClientContextStatus? _sspiClientContextStatus;

        internal override void GenerateSspiClientContext(ReadOnlyMemory<byte> received, ref byte[] sendBuff, ref uint sendLength, byte[][] _sniSpnBuffer)
        {
            _sspiClientContextStatus ??= new SspiClientContextStatus();

            SspiUtil.GenSspiClientContext(_sspiClientContextStatus, received, ref sendBuff, _sniSpnBuffer);
            SqlClientEventSource.Log.TryTraceEvent("TdsParserStateObjectManaged.GenerateSspiClientContext | Info | Session Id {0}", _physicalStateObj.SessionId);
            sendLength = (uint)(sendBuff != null ? sendBuff.Length : 0);
        }
    }
}
#endif

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET8_0_OR_GREATER

using System;
using System.Text;
using System.Net.Security;

#nullable enable

namespace Microsoft.Data.SqlClientX.Net.Security
{
    internal sealed class NegotiateSSPIContextProvider : SSPIContextProvider
    {
        private NegotiateAuthentication? _negotiateAuth = null;

        internal override void GenerateSspiClientContext(ReadOnlyMemory<byte> received, ref byte[] sendBuff, ref uint sendLength, byte[][] _sniSpnBuffer)
        {
            _negotiateAuth ??= new(new NegotiateAuthenticationClientOptions { Package = "Negotiate", TargetName = Encoding.Unicode.GetString(_sniSpnBuffer[0]) });
            sendBuff = _negotiateAuth.GetOutgoingBlob(received.Span, out NegotiateAuthenticationStatusCode statusCode)!;
            SqlClientEventSource.Log.TryTraceEvent("TdsParserStateObjectManaged.GenerateSspiClientContext | Info | Session Id {0}, StatusCode={1}", _physicalStateObj.SessionId, statusCode);
            if (statusCode is not NegotiateAuthenticationStatusCode.Completed and not NegotiateAuthenticationStatusCode.ContinueNeeded)
            {
                throw new InvalidOperationException(SQLMessage.SSPIGenerateError() + Environment.NewLine + statusCode);
            }
            sendLength = (uint)(sendBuff != null ? sendBuff.Length : 0);
        }
    }
}
#endif

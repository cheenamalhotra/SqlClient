// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;

namespace Microsoft.Data.SqlClientX.Net.Security
{
    internal static class SspiUtil
    {
#if !NET7_0_OR_GREATER
        /// <summary>
        /// Generate SSPI context
        /// </summary>
        /// <param name="sspiClientContextStatus">SSPI client context status</param>
        /// <param name="receivedBuff">Receive buffer</param>
        /// <param name="sendBuff">Send buffer</param>
        /// <param name="serverName">Service Principal Name buffer</param>
        /// <returns>SNI error code</returns>
        internal static void GenSspiClientContext(SspiClientContextStatus sspiClientContextStatus, ReadOnlyMemory<byte> receivedBuff, ref byte[] sendBuff, byte[][] serverName)
        {
            // TODO: this should use ReadOnlyMemory all the way through
            byte[] array = null;

            if (!receivedBuff.IsEmpty)
            {
                array = new byte[receivedBuff.Length];
                receivedBuff.CopyTo(array);
            }

            GenSspiClientContext(sspiClientContextStatus, array, ref sendBuff, serverName);
        }

        private static void GenSspiClientContext(SspiClientContextStatus sspiClientContextStatus, byte[] receivedBuff, ref byte[] sendBuff, byte[][] serverName)
        {
            SafeDeleteContext securityContext = sspiClientContextStatus.SecurityContext;
            ContextFlagsPal contextFlags = sspiClientContextStatus.ContextFlags;
            SafeFreeCredentials credentialsHandle = sspiClientContextStatus.CredentialsHandle;

            string securityPackage = NegotiationInfoClass.Negotiate;

            if (securityContext == null)
            {
                credentialsHandle = NegotiateStreamPal.AcquireDefaultCredential(securityPackage, false);
            }

            SecurityBuffer[] inSecurityBufferArray;
            if (receivedBuff != null)
            {
                inSecurityBufferArray = new SecurityBuffer[] { new SecurityBuffer(receivedBuff, SecurityBufferType.SECBUFFER_TOKEN) };
            }
            else
            {
                inSecurityBufferArray = Array.Empty<SecurityBuffer>();
            }

            int tokenSize = NegotiateStreamPal.QueryMaxTokenSize(securityPackage);

            SecurityBuffer outSecurityBuffer = new SecurityBuffer(tokenSize, SecurityBufferType.SECBUFFER_TOKEN);

            ContextFlagsPal requestedContextFlags = ContextFlagsPal.Connection
                | ContextFlagsPal.Confidentiality
                | ContextFlagsPal.Delegate
                | ContextFlagsPal.MutualAuth;

            string[] serverSPNs = new string[serverName.Length];
            for (int i = 0; i < serverName.Length; i++)
            {
                serverSPNs[i] = Encoding.Unicode.GetString(serverName[i]);
            }
            SecurityStatusPal statusCode = NegotiateStreamPal.InitializeSecurityContext(
                       credentialsHandle,
                       ref securityContext,
                       serverSPNs,
                       requestedContextFlags,
                       inSecurityBufferArray,
                       outSecurityBuffer,
                       ref contextFlags);

            if (statusCode.ErrorCode == SecurityStatusPalErrorCode.CompleteNeeded ||
                statusCode.ErrorCode == SecurityStatusPalErrorCode.CompAndContinue)
            {
                inSecurityBufferArray = new SecurityBuffer[] { outSecurityBuffer };
                statusCode = NegotiateStreamPal.CompleteAuthToken(ref securityContext, inSecurityBufferArray);
                outSecurityBuffer.token = null;
            }

            sendBuff = outSecurityBuffer.token;
            if (sendBuff == null)
            {
                sendBuff = Array.Empty<byte>();
            }

            sspiClientContextStatus.SecurityContext = securityContext;
            sspiClientContextStatus.ContextFlags = contextFlags;
            sspiClientContextStatus.CredentialsHandle = credentialsHandle;

            if (IsErrorStatus(statusCode.ErrorCode))
            {
                // Could not access Kerberos Ticket.
                //
                // SecurityStatusPalErrorCode.InternalError only occurs in Unix and always comes with a GssApiException,
                // so we don't need to check for a GssApiException here.
                if (statusCode.ErrorCode == SecurityStatusPalErrorCode.InternalError)
                {
                    throw new InvalidOperationException(SQLMessage.KerberosTicketMissingError() + Environment.NewLine + statusCode);
                }
                else
                {
                    throw new InvalidOperationException(SQLMessage.SSPIGenerateError() + Environment.NewLine + statusCode);
                }
            }
        }

        private static bool IsErrorStatus(SecurityStatusPalErrorCode errorCode)
        {
            return errorCode != SecurityStatusPalErrorCode.NotSet &&
                errorCode != SecurityStatusPalErrorCode.OK &&
                errorCode != SecurityStatusPalErrorCode.ContinueNeeded &&
                errorCode != SecurityStatusPalErrorCode.CompleteNeeded &&
                errorCode != SecurityStatusPalErrorCode.CompAndContinue &&
                errorCode != SecurityStatusPalErrorCode.ContextExpired &&
                errorCode != SecurityStatusPalErrorCode.CredentialsNeeded &&
                errorCode != SecurityStatusPalErrorCode.Renegotiate;
        }
#endif
    }
}

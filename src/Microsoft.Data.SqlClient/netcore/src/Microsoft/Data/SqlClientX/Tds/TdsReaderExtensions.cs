// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClientX.IO;
using Microsoft.Data.SqlClientX.Tds.State;

namespace Microsoft.Data.SqlClientX.Tds
{
    internal static class TdsReaderExtensions
    {
        public static async ValueTask<string> ReadByteStringAsync(this TdsReader tdsReader, bool isAsync, CancellationToken ct)
        {
            byte len = await tdsReader.ReadByteAsync(isAsync, ct).ConfigureAwait(false);
            return await tdsReader.ReadStringAsync(len, isAsync, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Returns the data stream length of the data identified by tds type or SqlMetaData 
        /// Returns either the total size or the size of the first chunk for partially length prefixed types.
        /// </summary>
        /// <param name="reader">Tds Reader</param>
        /// <param name="context">Command Handler Context</param>
        /// <param name="colmeta">Column metadata</param>
        /// <param name="isAsync">Whether caller method is executing asynchronously.</param>
        /// <param name="ct">Cancellation Token</param>
        /// <returns></returns>
        internal static async ValueTask<ulong> GetDataLengthAsync(this TdsReader reader, TdsCommandContext context, SqlMetaDataPriv colmeta, bool isAsync, CancellationToken ct)
        {
            // Handle 2005 specific tokens
            if (colmeta.metaType.IsPlp)
            {
                Debug.Assert(colmeta.tdsType == TdsEnums.SQLXMLTYPE ||
                             colmeta.tdsType == TdsEnums.SQLBIGVARCHAR ||
                             colmeta.tdsType == TdsEnums.SQLBIGVARBINARY ||
                             colmeta.tdsType == TdsEnums.SQLNVARCHAR ||
                             // Large UDTs is WinFS-only
                             colmeta.tdsType == TdsEnums.SQLUDT,
                             "GetDataLength:Invalid streaming datatype");
                return await reader.ReadPlpLengthAsync(context, true, colmeta.tdsType, isAsync, ct).ConfigureAwait(false);
            }
            else
            {
                return (ulong)await reader.ReadTokenLengthAsync(colmeta.tdsType, isAsync, ct).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// Utility to read token length for provided <paramref name="token"/> from Tds Stream.
        /// Returns -1 for partially length prefixed (plp) types for metadata info.
        /// Plp data streams length information should be obtained from <see cref="ReadPlpLengthAsync(TdsReader, TdsCommandContext, bool, ulong, bool, CancellationToken)"/>
        /// </summary>
        /// <param name="reader">TDS Reader instance</param>
        /// <param name="token">TDS Packet token</param>
        /// <param name="isAsync">Whether caller method is executing asynchronously.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>Token length as read from Tds Stream.</returns>
        internal static async ValueTask<int> ReadTokenLengthAsync(this TdsReader reader, byte token, bool isAsync, CancellationToken ct)
        {
            Debug.Assert(token != 0, "0 length token!");

            // Special cases with predefined return values
            switch (token)
            {
                case TdsEnums.SQLFEATUREEXTACK:
                case TdsEnums.SQLUDT: // special case for UDTs
                case TdsEnums.SQLRETURNVALUE: // In 2005, the RETURNVALUE token stream no longer has length
                    return -1;

                case TdsEnums.SQLSESSIONSTATE:
                case TdsEnums.SQLFEDAUTHINFO:
                    return await reader.ReadInt32Async(isAsync, ct).ConfigureAwait(false);

                case TdsEnums.SQLXMLTYPE:
                    return await reader.ReadUInt16Async(isAsync, ct).ConfigureAwait(false);
            }

            switch (token & TdsEnums.SQLLenMask)
            {
                case TdsEnums.SQLFixedLen:
                    return (0x01 << ((token & 0x0c) >> 2)) & 0xff;

                case TdsEnums.SQLZeroLen:
                    return 0;

                case TdsEnums.SQLVarLen:
                case TdsEnums.SQLVarCnt:
                    if ((token & 0x80) != 0)
                    {
                        return await reader.ReadUInt16Async(isAsync, ct).ConfigureAwait(false);
                    }
                    else if ((token & 0x0c) == 0)
                    {
                        return await reader.ReadInt32Async(isAsync, ct).ConfigureAwait(false);
                    }
                    else
                    {
                        return await reader.ReadByteAsync(isAsync, ct).ConfigureAwait(false);
                    }

                default:
                    Debug.Fail("Unknown token length!");
                    return 0;
            }
        }

        /// <summary>
        /// Reads the length of either the entire data or the length of the next chunk in a partially length prefixed data.
        /// After this call, call  ReadPlpBytes/ReadPlpUnicodeChars until the specified length of data is consumed.
        /// Repeat this until ReadPlpLength returns 0 in order to read the entire stream.
        /// When this function returns 0, it means the data stream is read completely and the plp state in the tdsparser is clean.
        /// </summary>
        /// <param name="reader">TDS Reader instance</param>
        /// <param name="context">Command Handler context</param>
        /// <param name="returnPlpNullIfNull">Whether to return Plp Null if data type is null.</param>
        /// <param name="tokenType">The type of token being read, if 0, this is first chunk of data.</param>
        /// <param name="isAsync">Whether caller method is executing asynchronously.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>Length Left in the PLP data stream.</returns>
        internal static async ValueTask<ulong> ReadPlpLengthAsync(this TdsReader reader, TdsCommandContext context, bool returnPlpNullIfNull, ulong tokenType, bool isAsync, CancellationToken ct)
        {
            // bool firstchunk = false;
            bool isNull = false;

            Debug.Assert(context.PlpLengthLeft == 0, "Out of synch length read request");
            if (context.PlpLength == 0)
            {
                // First chunk is being read. Find out what type of chunk it is
                long value = await reader.ReadInt64Async(isAsync, ct).ConfigureAwait(false);
                context.PlpLength = (ulong)value;
                // firstchunk = true;
            }

            if (context.PlpLength == TdsEnums.SQL_PLP_NULL)
            {
                context.PlpLength = 0;
                context.PlpLengthLeft = 0;
                isNull = true;
            }
            else
            {
                // Data is coming in uint chunks, read length of next chunk
                int chunkLength = (int)await reader.ReadUInt32Async(isAsync, ct).ConfigureAwait(false);

                if (chunkLength == TdsEnums.SQL_PLP_CHUNK_TERMINATOR)
                {
                    context.PlpLengthLeft = 0;
                }
                else
                {
                    context.PlpLengthLeft = (ulong)chunkLength;
                }
            }

            // AssertValidState();

            if (isNull && returnPlpNullIfNull)
            {
                return TdsEnums.SQL_PLP_NULL;
            }

            return context.PlpLengthLeft;

        }

    }
}

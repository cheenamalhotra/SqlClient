// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClientX.TDS.Handlers
{
    internal interface IBufferTypesHandler: IBufferHandler
    {
        public Task<Tuple<bool, byte>> ReadByteAsync();
        public Task<Tuple<bool, int>> ReadByteArrayAsync(Span<byte> buff, int len);
        public Task<Tuple<bool, char>> ReadCharAsync();
        public Task<Tuple<bool, char[]>> ReadCharsAsync();
        public Task<Tuple<bool, short>> ReadInt16Async();
        public Task<Tuple<bool, int>> ReadInt32Async();
        public Task<Tuple<bool, long>> ReadInt64Async();
        public Task<Tuple<bool, ushort>> ReadUInt16Async();
        public Task<Tuple<bool, uint>> ReadUInt32Async();
        public Task<Tuple<bool, ulong>> ReadUInt64Async();
        public Task<Tuple<bool, float>> ReadFloatAsync();
        public Task<Tuple<bool, double>> ReadDoubleAsync();
        public Task<Tuple<bool, string>> ReadStringAsync(int length);
        public Task<Tuple<bool, string>> ReadEncodedStringAsync(int length, System.Text.Encoding encoding, bool isPlp);
        public Task<Tuple<bool, int>> ReadPlpLengthAsync(bool returnPlpNullIfNull);
        public Task<Tuple<bool, byte[], int>> ReadPlpBytesAsync(ref byte[] buff, int offset, int len);
        public Task<Tuple<bool>> SkipLongBytesAsync(long num);
        public Task<Tuple<bool>> SkipIntBytesAsync(int num);
    }
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClientX.TDS.Handlers
{
    internal class BufferTypesHandler : BufferHandler, IBufferTypesHandler
    {
        public BufferTypesHandler(INetworkHandler networkHandler, IStateHandler stateHandler) : base(networkHandler, stateHandler)
        { }

        public async Task<Tuple<bool, byte>> ReadByteAsync()
        {
            TdsParser.ReliabilitySection.Assert("unreliable call to ReadByte");  // you need to setup for a thread abort somewhere before you call this method
            Debug.Assert(_inBytesUsed >= 0 && _inBytesUsed <= _inBytesRead, "ERROR - TDSParser: _inBytesUsed < 0 or _inBytesUsed > _inBytesRead");
            byte value = 0;

            if ((_inBytesPacket == 0) || (_inBytesUsed == _inBytesRead))
            {
                if (!await PrepareBufferAsync())
                {
                    return false;
                }
            }

            // decrement the number of bytes left in the packet
            _inBytesPacket--;

            Debug.Assert(_inBytesPacket >= 0, "ERROR - TDSParser: _inBytesPacket < 0");

            // return the byte from the buffer and increment the counter for number of bytes used in the in buffer
            value = (_inBuff[_inBytesUsed++]);

            AssertValidState();
            return new Tuple<bool, byte>(true, value);
        }

        public async Task<Tuple<bool, int>> ReadByteArrayAsync(ReadOnlyMemory<byte> buff, int len)
        {
            TdsParser.ReliabilitySection.Assert("unreliable call to ReadByteArray");  // you need to setup for a thread abort somewhere before you call this method
            int totalRead = 0;

            Debug.Assert(buff.IsEmpty || buff.Length >= len, "Invalid length sent to ReadByteArray()!");

            // loop through and read up to array length
            while (len > 0)
            {
                if ((_inBytesPacket == 0) || (_inBytesUsed == _inBytesRead))
                {
                    if (!await PrepareBufferAsync())
                    {
                        return new Tuple<bool, int>(false, totalRead);
                    }
                }

                int bytesToRead = Math.Min(len, Math.Min(_inBytesPacket, _inBytesRead - _inBytesUsed));
                Debug.Assert(bytesToRead > 0, "0 byte read in TryReadByteArray");
                if (!buff.IsEmpty)
                {
                    ReadOnlySpan<byte> copyFrom = new ReadOnlySpan<byte>(_inBuff, _inBytesUsed, bytesToRead);
                    Span<byte> copyTo = buff.Slice(totalRead, bytesToRead);
                    copyFrom.CopyTo(copyTo);
                }

                totalRead += bytesToRead;
                _inBytesUsed += bytesToRead;
                _inBytesPacket -= bytesToRead;
                len -= bytesToRead;

                AssertValidState();
            }

            return new Tuple<bool, int>(true, totalRead);
        }

        public async Task<Tuple<bool, char>> ReadCharAsync()
        {

        }

        public async Task<Tuple<bool, char[]>> ReadCharsAsync()
        {

        }

        public async Task<Tuple<bool, short>> ReadInt16Async()
        {
            short value = default;
            Span<byte> buffer = stackalloc byte[2];
            if (((_inBytesUsed + 2) > _inBytesRead) || (_inBytesPacket < 2))
            {
                // If the int16 isn't fully in the buffer, or if it isn't fully in the packet,
                // then use ReadByteArray since the logic is there to take care of that.
                if (!await ReadByteArrayAsync(buffer, 2))
                {
                    return new Tuple<bool, short>(false, value);
                }
            }
            else
            {
                // The entire int16 is in the packet and in the buffer, so just return it
                // and take care of the counters.
                buffer = _inBuff.AsSpan(_inBytesUsed, 2);
                _inBytesUsed += 2;
                _inBytesPacket -= 2;
            }

            AssertValidState();
            value = (short)((buffer[1] << 8) + buffer[0]);
            return new Tuple<bool, short>(true, value);
        }
    }
}

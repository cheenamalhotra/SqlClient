using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Data.SqlClientX.TDS.Helpers
{
    internal class TdsStreamReader : IDisposable
    {
        private readonly Stream _stream;
        private readonly Encoding _encoding;
        private readonly bool _leaveOpen;

        public TdsStreamReader(Stream stream, Encoding encoding, bool leaveOpen = false)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            _encoding = encoding ?? throw new ArgumentNullException(nameof(encoding));
            _leaveOpen = leaveOpen;
        }

        public async Task<byte> ReadByteAsync()
        {
            byte[] buffer = new byte[1];
            int bytesRead = await _stream.ReadAsync(buffer, 0, 1);
            if (bytesRead == 0)
            {
                throw new EndOfStreamException();
            }
            return buffer[0];
        }

        public async Task<ushort> ReadUInt16Async(CancellationToken cancellationToken)
        {
            Memory<byte> memory = new Memory<byte>(new byte[2]);
            // byte[] buffer = new byte[2];
            int bytesRead = await _stream.ReadAsync(memory, cancellationToken);
            if (bytesRead < 2)
            {
                throw new EndOfStreamException();
            }
            return bytesRead;
        }

        public async Task<int> ReadInt32Async()
        {
            byte[] buffer = new byte[4];
            int bytesRead = await _stream.ReadAsync(buffer, 0, 4);
            if (bytesRead < 4)
            {
                throw new EndOfStreamException();
            }
            return BitConverter.ToInt32(buffer, 0);
        }

        public async Task<string> ReadStringAsync(int length)
        {
            byte[] buffer = new byte[length];
            int bytesRead = await _stream.ReadAsync(buffer, 0, length);
            if (bytesRead < length)
            {
                throw new EndOfStreamException();
            }
            return _encoding.GetString(buffer);
        }

        public void Dispose()
        {
            if (!_leaveOpen)
            {
                _stream?.Dispose();
            }
        }
    }
}

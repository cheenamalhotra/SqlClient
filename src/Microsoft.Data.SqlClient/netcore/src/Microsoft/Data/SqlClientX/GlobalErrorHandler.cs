// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Threading;
using Microsoft.Data.SqlClient;
using Microsoft.Data.SqlClientX.Net.Types;

namespace Microsoft.Data.SqlClientX
{
    /// <summary>
    /// Global Networking settings and status
    /// </summary>
    internal class GlobalErrorHandler
    {
        public static readonly GlobalErrorHandler Instance = new();

        public readonly EncryptionOptions _encryptionOption = EncryptionOptions.OFF;
        public ThreadLocal<SqlNetworkError> _lastError = new(static () => new SqlNetworkError(Providers.INVALID_PROV, 0, TdsEnums.SNI_SUCCESS, string.Empty));

        private readonly uint _status = TdsEnums.SNI_SUCCESS;

        /// <summary>
        /// Last SNI error
        /// </summary>
        public SqlNetworkError LastError
        {
            get => _lastError.Value;
            set => _lastError.Value = value;
        }

        /// <summary>
        /// SNI library status
        /// </summary>
        public uint Status
        {
            get => _status;
        }

        /// <summary>
        /// Encryption options setting
        /// </summary>
        public EncryptionOptions Options
        {
            get => _encryptionOption;
        }

        /// <summary>
        /// Verify client encryption possibility
        /// </summary>
        // TODO: by adding support ENCRYPT_NOT_SUP, it could be calculated.
        public static bool ClientOSEncryptionSupport => true;
    }
}

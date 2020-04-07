﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;

namespace Microsoft.Data.SqlClient.FunctionalTests
{
    /// <summary>
    /// Dummy Key Store Provider.
    /// </summary>
    internal class AEDummyKeyStoreProviderTest : SqlColumnEncryptionKeyStoreProvider
    {
        public override byte[] DecryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] encryptedColumnEncryptionKey)
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] columnEncryptionKey)
        {
            throw new NotImplementedException();
        }
    }
}
